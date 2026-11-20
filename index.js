import "dotenv/config";
import express from "express";
import cors from "cors";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";

const app = express();
const port = process.env.PORT || 5000;

app.use(
  cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
  })
);
app.use(express.json());

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

    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  } catch (error) {
    console.error("Failed to connect to MongoDB:", error.message);
    process.exit(1);
  }
}

run();