import "dotenv/config";
import express from "express";
import cors from "cors";
import { MongoClient, ServerApiVersion } from "mongodb";

const app = express();
const port = process.env.PORT || 5000;

app.use(
  cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
  })
);
app.use(express.json());

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

    app.get("/services", async (req, res) => {
      try {
        const services = await servicesCollection
          .find({ status: "approved" })
          .toArray();
        res.json(services);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch services" });
      }
    });

    app.post("/services", async (req, res) => {
      try {
        const service = {
          ...req.body,
          status: "pending",
          createdAt: new Date(),
        };
        const result = await servicesCollection.insertOne(service);
        res.status(201).json(result);
      } catch (error) {
        res.status(500).json({ message: "Failed to add service" });
      }
    });

    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  } catch (error) {
    console.error("Failed to connect to MongoDB:", error.message);
    process.exit(1);
  }
}

run();