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

        const query = { status: "approved" };

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

    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  } catch (error) {
    console.error("Failed to connect to MongoDB:", error.message);
    process.exit(1);
  }
}

run();