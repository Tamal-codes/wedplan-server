import "dotenv/config";
import express from "express";
import cors from "cors";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";
import Stripe from "stripe";

const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const port = process.env.PORT || 5000;

app.use(
  cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
  })
);

// ওয়েবহুকের জন্য raw body লাগে, তাই ওই রুটে json পার্সার চলবে না
app.use((req, res, next) => {
  if (req.originalUrl === "/webhook") return next();
  express.json()(req, res, next);
});

const JWKS = createRemoteJWKSet(new URL(process.env.JWKS_URL));

const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    const db = client.db(process.env.DB_NAME);
    console.log("MongoDB connected");

    const servicesCollection = db.collection("services");
    const usersCollection = db.collection("user");
    const bookingsCollection = db.collection("bookings");
    const transactionsCollection = db.collection("transactions");

    // JWT যাচাই: টোকেন ঠিক কিনা, আর ইউজার ব্লক কিনা
    const verifyToken = async (req, res, next) => {
      try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
          return res
            .status(401)
            .json({ message: "Unauthorized: token missing" });
        }

        const token = authHeader.split(" ")[1];
        const { payload } = await jwtVerify(token, JWKS);

        // টোকেনের রোল বিশ্বাস না করে ডাটাবেস থেকে আসল রোল নেওয়া হচ্ছে
        const user = await usersCollection.findOne({
          _id: new ObjectId(payload.id),
        });

        if (!user) {
          return res
            .status(401)
            .json({ message: "Unauthorized: user not found" });
        }
        if (user.isBlocked) {
          return res
            .status(403)
            .json({ message: "Forbidden: account blocked" });
        }

        req.user = {
          id: user._id.toString(),
          email: user.email,
          name: user.name,
          role: user.role,
        };
        next();
      } catch (error) {
        return res
          .status(401)
          .json({ message: "Unauthorized: invalid or expired token" });
      }
    };

    // রোল যাচাই: শুধু নির্দিষ্ট রোল ঢুকতে পারবে
    const verifyRole =
      (...roles) =>
      (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
          return res.status(403).json({ message: "Forbidden: access denied" });
        }
        next();
      };

    app.get("/me", verifyToken, (req, res) => {
      res.json(req.user);
    });

    app.get("/services", async (req, res) => {
      try {
        const { search, category, location, sort } = req.query;

        const query = { status: "approved", isAvailable: { $ne: false } };

        if (search) {
          query.serviceName = { $regex: search, $options: "i" };
        }
        if (category) {
          query.category = category;
        }
        if (location) {
          query.location = { $regex: location, $options: "i" };
        }

        let sortOption = {};
        if (sort === "price_asc") sortOption = { price: 1 };
        if (sort === "price_desc") sortOption = { price: -1 };

        const services = await servicesCollection
          .find(query)
          .sort(sortOption)
          .toArray();

        res.json(services);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch services" });
      }
    });

    app.get("/services/:id", async (req, res) => {
      try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: "Invalid service ID" });
        }

        const service = await servicesCollection.findOne({
          _id: new ObjectId(id),
          status: "approved",
          isAvailable: { $ne: false },
        });

        if (!service) {
          return res.status(404).json({ message: "Service not found" });
        }

        res.json(service);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch service" });
      }
    });

    app.post(
      "/services",
      verifyToken,
      verifyRole("vendor"),
      async (req, res) => {
        try {
          const {
            serviceName,
            category,
            description,
            price,
            location,
            images,
          } = req.body;

          if (
            !serviceName?.trim() ||
            !category?.trim() ||
            !description?.trim() ||
            !location?.trim() ||
            !Number.isFinite(Number(price)) ||
            Number(price) <= 0 ||
            !Array.isArray(images) ||
            images.length === 0
          ) {
            return res.status(400).json({
              message: "All fields and at least one image are required",
            });
          }

          const vendor = await usersCollection.findOne({
            _id: new ObjectId(req.user.id),
          });
          const isPremium =
            vendor.subscriptionPlan === "premium" &&
            vendor.subscriptionExpiresAt &&
            new Date(vendor.subscriptionExpiresAt) > new Date();

          if (!isPremium) {
            const activeCount = await servicesCollection.countDocuments({
              vendorId: req.user.id,
              status: { $in: ["pending", "approved"] },
            });
            if (activeCount >= 3) {
              return res.status(403).json({
                message:
                  "Free plan limit reached (3 services). Upgrade to Premium.",
              });
            }
          }

          const service = {
            vendorId: req.user.id,
            vendorName: vendor.businessName || vendor.name,
            serviceName: serviceName.trim(),
            category: category.trim(),
            description: description.trim(),
            price: Number(price),
            location: location.trim(),
            images,
            status: "pending",
            createdAt: new Date(),
          };

          const result = await servicesCollection.insertOne(service);
          res.status(201).json({ _id: result.insertedId, ...service });
        } catch (error) {
          res.status(500).json({ message: "Failed to add service" });
        }
      }
    );

    app.get(
      "/vendor/services",
      verifyToken,
      verifyRole("vendor"),
      async (req, res) => {
        try {
          const services = await servicesCollection
            .find({ vendorId: req.user.id })
            .sort({ createdAt: -1 })
            .toArray();
          res.json(services);
        } catch (error) {
          res.status(500).json({ message: "Failed to fetch your services" });
        }
      }
    );

    // ভেন্ডরের নিজের একটা সার্ভিস (যেকোনো স্ট্যাটাস)
    app.get(
      "/vendor/services/:id",
      verifyToken,
      verifyRole("vendor"),
      async (req, res) => {
        try {
          const { id } = req.params;
          if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid service ID" });
          }
          const service = await servicesCollection.findOne({
            _id: new ObjectId(id),
            vendorId: req.user.id,
          });
          if (!service) {
            return res.status(404).json({ message: "Service not found" });
          }
          res.json(service);
        } catch (error) {
          res.status(500).json({ message: "Failed to fetch service" });
        }
      }
    );

    app.patch(
      "/services/:id",
      verifyToken,
      verifyRole("vendor"),
      async (req, res) => {
        try {
          const { id } = req.params;
          if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid service ID" });
          }

          const service = await servicesCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!service) {
            return res.status(404).json({ message: "Service not found" });
          }
          if (service.vendorId !== req.user.id) {
            return res
              .status(403)
              .json({ message: "Forbidden: not your service" });
          }

          const {
            serviceName,
            category,
            description,
            price,
            location,
            images,
          } = req.body;
          const updates = {};

          if (serviceName !== undefined) {
            if (!serviceName.trim()) {
              return res.status(400).json({ message: "Invalid service name" });
            }
            updates.serviceName = serviceName.trim();
          }
          if (category !== undefined) updates.category = category.trim();
          if (description !== undefined)
            updates.description = description.trim();
          if (location !== undefined) updates.location = location.trim();
          if (price !== undefined) {
            if (!Number.isFinite(Number(price)) || Number(price) <= 0) {
              return res.status(400).json({ message: "Invalid price" });
            }
            updates.price = Number(price);
          }
          if (images !== undefined) {
            if (!Array.isArray(images) || images.length === 0) {
              return res
                .status(400)
                .json({ message: "At least one image is required" });
            }
            updates.images = images;
          }

          if (Object.keys(updates).length === 0) {
            return res.status(400).json({ message: "Nothing to update" });
          }

          await servicesCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: updates }
          );
          res.json({ message: "Service updated" });
        } catch (error) {
          res.status(500).json({ message: "Failed to update service" });
        }
      }
    );

    app.patch(
      "/services/:id/availability",
      verifyToken,
      verifyRole("vendor"),
      async (req, res) => {
        try {
          const { id } = req.params;
          if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid service ID" });
          }
          if (typeof req.body.isAvailable !== "boolean") {
            return res
              .status(400)
              .json({ message: "isAvailable must be true or false" });
          }

          const service = await servicesCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!service) {
            return res.status(404).json({ message: "Service not found" });
          }
          if (service.vendorId !== req.user.id) {
            return res
              .status(403)
              .json({ message: "Forbidden: not your service" });
          }

          await servicesCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { isAvailable: req.body.isAvailable } }
          );
          res.json({ message: "Availability updated" });
        } catch (error) {
          res.status(500).json({ message: "Failed to update availability" });
        }
      }
    );

    app.delete(
      "/services/:id",
      verifyToken,
      verifyRole("vendor"),
      async (req, res) => {
        try {
          const { id } = req.params;
          if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid service ID" });
          }

          const service = await servicesCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!service) {
            return res.status(404).json({ message: "Service not found" });
          }
          if (service.vendorId !== req.user.id) {
            return res
              .status(403)
              .json({ message: "Forbidden: not your service" });
          }

          await servicesCollection.deleteOne({ _id: new ObjectId(id) });
          res.json({ message: "Service deleted" });
        } catch (error) {
          res.status(500).json({ message: "Failed to delete service" });
        }
      }
    );

    // বুকিং রিকোয়েস্ট পাঠানো (শুধু customer)
    app.post(
      "/bookings",
      verifyToken,
      verifyRole("customer"),
      async (req, res) => {
        try {
          const { serviceId, eventDate, eventLocation, message } = req.body;

          if (!ObjectId.isValid(serviceId)) {
            return res.status(400).json({ message: "Invalid service ID" });
          }
          if (!eventLocation?.trim() || !eventDate) {
            return res
              .status(400)
              .json({ message: "Event date and location are required" });
          }

          const date = new Date(eventDate);
          if (isNaN(date.getTime())) {
            return res.status(400).json({ message: "Invalid event date" });
          }
          const today = new Date();
          today.setHours(0, 0, 0, 0);
          if (date < today) {
            return res
              .status(400)
              .json({ message: "Event date cannot be in the past" });
          }

          const service = await servicesCollection.findOne({
            _id: new ObjectId(serviceId),
            status: "approved",
            isAvailable: { $ne: false },
          });
          if (!service) {
            return res
              .status(404)
              .json({ message: "Service not found or unavailable" });
          }
          if (service.vendorId === req.user.id) {
            return res
              .status(403)
              .json({ message: "You cannot book your own service" });
          }

          // একই সার্ভিস ও তারিখে ডুপ্লিকেট active রিকোয়েস্ট আটকানো
          const duplicate = await bookingsCollection.findOne({
            serviceId,
            customerId: req.user.id,
            eventDate: date.toISOString().slice(0, 10),
            status: { $in: ["pending", "accepted"] },
          });
          if (duplicate) {
            return res.status(409).json({
              message: "You already have an active request for this date",
            });
          }

          const booking = {
            serviceId,
            vendorId: service.vendorId,
            customerId: req.user.id,
            eventDate: date.toISOString().slice(0, 10),
            eventLocation: eventLocation.trim(),
            message: (message ?? "").trim(),
            status: "pending",
            createdAt: new Date(),
          };
          const result = await bookingsCollection.insertOne(booking);
          res.status(201).json({ _id: result.insertedId, ...booking });
        } catch (error) {
          res.status(500).json({ message: "Failed to submit booking" });
        }
      }
    );

    // কাস্টমারের নিজের বুকিং (সার্ভিসের তথ্যসহ)
    app.get(
      "/customer/bookings",
      verifyToken,
      verifyRole("customer"),
      async (req, res) => {
        try {
          const bookings = await bookingsCollection
            .aggregate([
              { $match: { customerId: req.user.id } },
              { $sort: { createdAt: -1 } },
              {
                $addFields: { serviceObjId: { $toObjectId: "$serviceId" } },
              },
              {
                $lookup: {
                  from: "services",
                  localField: "serviceObjId",
                  foreignField: "_id",
                  as: "service",
                },
              },
              {
                $unwind: { path: "$service", preserveNullAndEmptyArrays: true },
              },
              { $project: { serviceObjId: 0 } },
            ])
            .toArray();
          res.json(bookings);
        } catch (error) {
          res.status(500).json({ message: "Failed to fetch bookings" });
        }
      }
    );

    // কাস্টমার pending বুকিং বাতিল করবে
    app.patch(
      "/bookings/:id/cancel",
      verifyToken,
      verifyRole("customer"),
      async (req, res) => {
        try {
          const { id } = req.params;
          if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid booking ID" });
          }
          const booking = await bookingsCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!booking) {
            return res.status(404).json({ message: "Booking not found" });
          }
          if (booking.customerId !== req.user.id) {
            return res
              .status(403)
              .json({ message: "Forbidden: not your booking" });
          }
          if (booking.status !== "pending") {
            return res
              .status(400)
              .json({ message: "Only pending bookings can be cancelled" });
          }
          await bookingsCollection.updateOne(
            { _id: new ObjectId(id), status: "pending" },
            { $set: { status: "cancelled" } }
          );
          res.json({ message: "Booking cancelled" });
        } catch (error) {
          res.status(500).json({ message: "Failed to cancel booking" });
        }
      }
    );

    // ভেন্ডরের সার্ভিসের সব বুকিং (কাস্টমার ও সার্ভিসের তথ্যসহ)
    app.get(
      "/vendor/bookings",
      verifyToken,
      verifyRole("vendor"),
      async (req, res) => {
        try {
          const bookings = await bookingsCollection
            .aggregate([
              { $match: { vendorId: req.user.id } },
              { $sort: { createdAt: -1 } },
              {
                $addFields: {
                  serviceObjId: { $toObjectId: "$serviceId" },
                  customerObjId: { $toObjectId: "$customerId" },
                },
              },
              {
                $lookup: {
                  from: "services",
                  localField: "serviceObjId",
                  foreignField: "_id",
                  as: "service",
                },
              },
              {
                $lookup: {
                  from: "user",
                  localField: "customerObjId",
                  foreignField: "_id",
                  as: "customer",
                },
              },
              {
                $unwind: { path: "$service", preserveNullAndEmptyArrays: true },
              },
              {
                $unwind: {
                  path: "$customer",
                  preserveNullAndEmptyArrays: true,
                },
              },
              {
                $project: {
                  serviceObjId: 0,
                  customerObjId: 0,
                  "customer.password": 0,
                },
              },
            ])
            .toArray();
          res.json(bookings);
        } catch (error) {
          res.status(500).json({ message: "Failed to fetch bookings" });
        }
      }
    );

    // ভেন্ডর accept/reject (শুধু pending, শুধু নিজের সার্ভিসের)
    app.patch(
      "/bookings/:id/status",
      verifyToken,
      verifyRole("vendor"),
      async (req, res) => {
        try {
          const { id } = req.params;
          const { status } = req.body;
          if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid booking ID" });
          }
          if (!["accepted", "rejected"].includes(status)) {
            return res
              .status(400)
              .json({ message: "Status must be accepted or rejected" });
          }
          const booking = await bookingsCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!booking) {
            return res.status(404).json({ message: "Booking not found" });
          }
          if (booking.vendorId !== req.user.id) {
            return res
              .status(403)
              .json({ message: "Forbidden: not your booking" });
          }
          if (booking.status !== "pending") {
            return res
              .status(400)
              .json({ message: "Only pending requests can be processed" });
          }
          await bookingsCollection.updateOne(
            { _id: new ObjectId(id), status: "pending" },
            { $set: { status } }
          );
          res.json({ message: `Booking ${status}` });
        } catch (error) {
          res.status(500).json({ message: "Failed to update booking" });
        }
      }
    );

    // ================= ADMIN APIs =================

    // ড্যাশবোর্ড পরিসংখ্যান
    app.get(
      "/admin/stats",
      verifyToken,
      verifyRole("admin"),
      async (req, res) => {
        try {
          const [
            totalUsers,
            totalVendors,
            totalCustomers,
            totalServices,
            pendingServices,
            totalTransactions,
          ] = await Promise.all([
            usersCollection.countDocuments(),
            usersCollection.countDocuments({ role: "vendor" }),
            usersCollection.countDocuments({ role: "customer" }),
            servicesCollection.countDocuments(),
            servicesCollection.countDocuments({ status: "pending" }),
            transactionsCollection.countDocuments(),
          ]);
          res.json({
            totalUsers,
            totalVendors,
            totalCustomers,
            totalServices,
            pendingServices,
            totalTransactions,
          });
        } catch (error) {
          res.status(500).json({ message: "Failed to fetch stats" });
        }
      }
    );

    // সব ইউজার (সার্চ ও রোল ফিল্টার সহ)
    app.get(
      "/admin/users",
      verifyToken,
      verifyRole("admin"),
      async (req, res) => {
        try {
          const { search, role } = req.query;
          const query = {};

          if (search) {
            query.$or = [
              { name: { $regex: search, $options: "i" } },
              { email: { $regex: search, $options: "i" } },
            ];
          }
          if (role && ["admin", "vendor", "customer"].includes(role)) {
            query.role = role;
          }

          const users = await usersCollection
            .find(query)
            .project({ password: 0 })
            .sort({ createdAt: -1 })
            .toArray();
          res.json(users);
        } catch (error) {
          res.status(500).json({ message: "Failed to fetch users" });
        }
      }
    );

    // ইউজার ব্লক/আনব্লক
    app.patch(
      "/admin/users/:id/block",
      verifyToken,
      verifyRole("admin"),
      async (req, res) => {
        try {
          const { id } = req.params;
          const { isBlocked } = req.body;

          if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid user ID" });
          }
          if (typeof isBlocked !== "boolean") {
            return res
              .status(400)
              .json({ message: "isBlocked must be true or false" });
          }
          if (id === req.user.id) {
            return res
              .status(400)
              .json({ message: "You cannot block yourself" });
          }

          const target = await usersCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!target) {
            return res.status(404).json({ message: "User not found" });
          }
          if (target.role === "admin") {
            return res
              .status(403)
              .json({ message: "Admin accounts cannot be blocked" });
          }

          await usersCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { isBlocked } }
          );
          res.json({ message: isBlocked ? "User blocked" : "User unblocked" });
        } catch (error) {
          res.status(500).json({ message: "Failed to update user" });
        }
      }
    );

    // সব সার্ভিস (যেকোনো স্ট্যাটাস, সার্চ ও ফিল্টার সহ)
    app.get(
      "/admin/services",
      verifyToken,
      verifyRole("admin"),
      async (req, res) => {
        try {
          const { search, status, category } = req.query;
          const query = {};

          if (search) {
            query.serviceName = { $regex: search, $options: "i" };
          }
          if (status && ["pending", "approved", "rejected"].includes(status)) {
            query.status = status;
          }
          if (category) {
            query.category = category;
          }

          const services = await servicesCollection
            .find(query)
            .sort({ createdAt: -1 })
            .toArray();
          res.json(services);
        } catch (error) {
          res.status(500).json({ message: "Failed to fetch services" });
        }
      }
    );

    // সার্ভিস approve/reject/pending
    app.patch(
      "/admin/services/:id/status",
      verifyToken,
      verifyRole("admin"),
      async (req, res) => {
        try {
          const { id } = req.params;
          const { status } = req.body;

          if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid service ID" });
          }
          if (!["pending", "approved", "rejected"].includes(status)) {
            return res.status(400).json({ message: "Invalid status" });
          }

          const result = await servicesCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { status } }
          );
          if (result.matchedCount === 0) {
            return res.status(404).json({ message: "Service not found" });
          }
          res.json({ message: `Service ${status}` });
        } catch (error) {
          res.status(500).json({ message: "Failed to update service" });
        }
      }
    );

    // অনুপযুক্ত সার্ভিস ডিলিট
    app.delete(
      "/admin/services/:id",
      verifyToken,
      verifyRole("admin"),
      async (req, res) => {
        try {
          const { id } = req.params;
          if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid service ID" });
          }
          const result = await servicesCollection.deleteOne({
            _id: new ObjectId(id),
          });
          if (result.deletedCount === 0) {
            return res.status(404).json({ message: "Service not found" });
          }
          res.json({ message: "Service deleted" });
        } catch (error) {
          res.status(500).json({ message: "Failed to delete service" });
        }
      }
    );

    // ট্রানজ্যাকশন (শুধু দেখা যাবে, বদলানো যাবে না)
    app.get(
      "/admin/transactions",
      verifyToken,
      verifyRole("admin"),
      async (req, res) => {
        try {
          const transactions = await transactionsCollection
            .aggregate([
              { $sort: { createdAt: -1 } },
              {
                $addFields: { vendorObjId: { $toObjectId: "$vendorId" } },
              },
              {
                $lookup: {
                  from: "user",
                  localField: "vendorObjId",
                  foreignField: "_id",
                  as: "vendor",
                },
              },
              {
                $unwind: { path: "$vendor", preserveNullAndEmptyArrays: true },
              },
              {
                $project: {
                  vendorObjId: 0,
                  "vendor.password": 0,
                },
              },
            ])
            .toArray();
          res.json(transactions);
        } catch (error) {
          res.status(500).json({ message: "Failed to fetch transactions" });
        }
      }
    );

    // ================= PAYMENT (Stripe) =================

    // Premium কেনার Checkout Session (শুধু নিজের জন্য)
    app.post(
      "/subscription/checkout",
      verifyToken,
      verifyRole("vendor"),
      async (req, res) => {
        try {
          const vendor = await usersCollection.findOne({
            _id: new ObjectId(req.user.id),
          });
          const active =
            vendor.subscriptionPlan === "premium" &&
            vendor.subscriptionExpiresAt &&
            new Date(vendor.subscriptionExpiresAt) > new Date();
          if (active) {
            return res
              .status(400)
              .json({ message: "You already have an active Premium plan" });
          }

          const session = await stripe.checkout.sessions.create({
            mode: "payment",
            customer_email: vendor.email,
            line_items: [
              {
                quantity: 1,
                price_data: {
                  currency: "usd",
                  unit_amount: 2000,
                  product_data: { name: "WedPlan Premium (30 days)" },
                },
              },
            ],
            // vendorId টোকেন থেকে আসে, ক্লায়েন্টের পাঠানো আইডি নয়
            metadata: { vendorId: req.user.id },
            success_url: `${process.env.CLIENT_URL}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${process.env.CLIENT_URL}/payment/cancel`,
          });

          await transactionsCollection.insertOne({
            vendorId: req.user.id,
            plan: "premium",
            amount: 2000,
            currency: "usd",
            stripeSessionId: session.id,
            stripeSubscriptionId: null,
            status: "pending",
            createdAt: new Date(),
          });

          res.json({ url: session.url });
        } catch (error) {
          console.error("Checkout error:", error.message);
          res.status(500).json({ message: "Failed to start checkout" });
        }
      }
    );

    // সাবস্ক্রিপশনের বর্তমান অবস্থা (মেয়াদ শেষ হলে Free করে দেয়)
    app.get(
      "/subscription/status",
      verifyToken,
      verifyRole("vendor"),
      async (req, res) => {
        try {
          const vendor = await usersCollection.findOne({
            _id: new ObjectId(req.user.id),
          });
          const active =
            vendor.subscriptionPlan === "premium" &&
            vendor.subscriptionExpiresAt &&
            new Date(vendor.subscriptionExpiresAt) > new Date();

          if (vendor.subscriptionPlan === "premium" && !active) {
            await usersCollection.updateOne(
              { _id: vendor._id },
              { $set: { subscriptionPlan: "free" } }
            );
          }

          res.json({
            plan: active ? "premium" : "free",
            expiresAt: active ? vendor.subscriptionExpiresAt : null,
          });
        } catch (error) {
          res.status(500).json({ message: "Failed to fetch subscription" });
        }
      }
    );

    // Stripe ওয়েবহুক: এখানেই শুধু Premium চালু হয়
    app.post(
      "/webhook",
      express.raw({ type: "application/json" }),
      async (req, res) => {
        let event;
        try {
          event = stripe.webhooks.constructEvent(
            req.body,
            req.headers["stripe-signature"],
            process.env.STRIPE_WEBHOOK_SECRET
          );
        } catch (error) {
          return res.status(400).send("Webhook signature verification failed");
        }

        try {
          if (event.type === "checkout.session.completed") {
            const session = event.data.object;

            if (session.payment_status === "paid") {
              // একই ইভেন্ট দুইবার এলেও একবারই কাজ হবে
              const result = await transactionsCollection.updateOne(
                { stripeSessionId: session.id, status: { $ne: "paid" } },
                {
                  $set: {
                    status: "paid",
                    amount: session.amount_total,
                    currency: session.currency,
                    paidAt: new Date(),
                  },
                }
              );

              if (result.matchedCount === 1) {
                const vendorId = session.metadata?.vendorId;
                const vendor = await usersCollection.findOne({
                  _id: new ObjectId(vendorId),
                });
                if (vendor) {
                  const now = new Date();
                  const base =
                    vendor.subscriptionExpiresAt &&
                    new Date(vendor.subscriptionExpiresAt) > now
                      ? new Date(vendor.subscriptionExpiresAt)
                      : now;
                  const expires = new Date(
                    base.getTime() + 30 * 24 * 60 * 60 * 1000
                  );
                  await usersCollection.updateOne(
                    { _id: vendor._id },
                    {
                      $set: {
                        subscriptionPlan: "premium",
                        subscriptionExpiresAt: expires,
                      },
                    }
                  );
                }
              }
            }
          }

          if (event.type === "checkout.session.expired") {
            await transactionsCollection.updateOne(
              { stripeSessionId: event.data.object.id, status: "pending" },
              { $set: { status: "failed" } }
            );
          }

          res.json({ received: true });
        } catch (error) {
          res.status(500).send("Webhook handler failed");
        }
      }
    );

    // পেমেন্টের পর Stripe থেকে সরাসরি যাচাই করে Premium চালু
    app.post(
      "/subscription/confirm",
      verifyToken,
      verifyRole("vendor"),
      async (req, res) => {
        try {
          const { sessionId } = req.body;
          if (!sessionId || typeof sessionId !== "string") {
            return res.status(400).json({ message: "Session ID required" });
          }

          const session = await stripe.checkout.sessions.retrieve(sessionId);

          if (session.metadata?.vendorId !== req.user.id) {
            return res.status(403).json({ message: "Forbidden" });
          }
          if (session.payment_status !== "paid") {
            return res.status(400).json({ message: "Payment not completed" });
          }

          const result = await transactionsCollection.updateOne(
            { stripeSessionId: session.id, status: { $ne: "paid" } },
            {
              $set: {
                status: "paid",
                amount: session.amount_total,
                currency: session.currency,
                paidAt: new Date(),
              },
            }
          );

          if (result.matchedCount === 1) {
            const vendor = await usersCollection.findOne({
              _id: new ObjectId(req.user.id),
            });
            const now = new Date();
            const base =
              vendor.subscriptionExpiresAt &&
              new Date(vendor.subscriptionExpiresAt) > now
                ? new Date(vendor.subscriptionExpiresAt)
                : now;
            await usersCollection.updateOne(
              { _id: vendor._id },
              {
                $set: {
                  subscriptionPlan: "premium",
                  subscriptionExpiresAt: new Date(
                    base.getTime() + 30 * 24 * 60 * 60 * 1000
                  ),
                },
              }
            );
          }

          res.json({ message: "Premium activated" });
        } catch (error) {
          console.error("Confirm error:", error.message);
          res.status(500).json({ message: "Failed to confirm payment" });
        }
      }
    );

    // নিজের প্রোফাইল আপডেট (রোল, প্ল্যান, isBlocked বদলানো যাবে না)
    app.patch(
      "/profile",
      verifyToken,
      verifyRole("vendor", "customer"),
      async (req, res) => {
        try {
          const { name, image, businessName } = req.body;
          const updates = {};

          if (name !== undefined) {
            if (typeof name !== "string" || !name.trim()) {
              return res.status(400).json({ message: "Name is required" });
            }
            updates.name = name.trim();
          }
          if (image !== undefined) {
            if (typeof image !== "string") {
              return res.status(400).json({ message: "Invalid image" });
            }
            updates.image = image;
          }
          if (businessName !== undefined && req.user.role === "vendor") {
            if (typeof businessName !== "string") {
              return res.status(400).json({ message: "Invalid business name" });
            }
            updates.businessName = businessName.trim();
          }

          if (Object.keys(updates).length === 0) {
            return res.status(400).json({ message: "Nothing to update" });
          }

          updates.updatedAt = new Date();
          await usersCollection.updateOne(
            { _id: new ObjectId(req.user.id) },
            { $set: updates }
          );
          res.json({ message: "Profile updated" });
        } catch (error) {
          res.status(500).json({ message: "Failed to update profile" });
        }
      }
    );

    // ভেন্ডরের বুকিং পরিসংখ্যান
    app.get(
      "/vendor/stats",
      verifyToken,
      verifyRole("vendor"),
      async (req, res) => {
        try {
          const [pending, accepted] = await Promise.all([
            bookingsCollection.countDocuments({
              vendorId: req.user.id,
              status: "pending",
            }),
            bookingsCollection.countDocuments({
              vendorId: req.user.id,
              status: "accepted",
            }),
          ]);
          res.json({ pendingBookings: pending, acceptedBookings: accepted });
        } catch (error) {
          res.status(500).json({ message: "Failed to fetch stats" });
        }
      }
    );

    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  } catch (error) {
    console.error("Failed to connect to MongoDB:", error.message);
    process.exit(1);
  }
}

run();