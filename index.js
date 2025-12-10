import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient, ServerApiVersion } from "mongodb";
import admin from "firebase-admin";

dotenv.config();
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8"
);
const serviceAccount = JSON.parse(decoded);

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  cors({
    origin: ["http://localhost:5173"],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const uri = process.env.MONGODB_URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const verifyToken = async (req, res, next) => {
  const token = req.headers.authorization.split(" ")[1];
  if (!token) {
    return res.status(401).send("Unauthorized: No token provided");
  }
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.token_email = decoded.email;
    next();
  } catch (error) {
    return res.status(401).send("Unauthorized: Invalid token");
  }
};

const run = async () => {
  try {
    await client.connect();
    const db = client.db("garments");
    const users = db.collection("users");
    const products = db.collection("products");

    //Auth Routes
    app.post("/register", async (req, res) => {
      const { name, email, photoURL, role } = req.body;
      if (!name || !email || !photoURL) {
        res.status(400).json("Missing required fields");
        return;
      }
      const existingUser = await users.findOne({ email });
      if (existingUser) {
        res.status(400).json("User already exists");
        return;
      }
      const user = {
        name,
        email,
        photoURL,
        role,
        status: "pending",
      };
      await users.insertOne(user);
      res.status(201).json("User Registered");
    });

    app.post("/google-register", async (req, res) => {
      const { name, email, photoURL, role } = req.body;
      if (!name || !email || !photoURL) {
        res.status(400).json("Missing required fields");
        return;
      }
      const existingUser = await users.findOne({ email });
      if (existingUser) {
        return res.json({ success: true, existingUser });
      }
      const user = {
        name,
        email,
        photoURL,
        role: "buyer",
        status: "pending",
      };
      await users.insertOne(user);
      res.status(201).json("User Registered");
    });

    app.get("/users/:email", async (req, res) => {
      const email = decodeURIComponent(req.params.email);
      const user = await users.findOne({ email });
      if (!user) {
        res.status(404).json("User not found");
        return;
      }
      res.status(200).json(user);
    });

    // Admin Routes
    app.patch("/admin/user-status/:email", verifyToken, async (req, res) => {
      const email = decodeURIComponent(req.params.email);
      const { status } = req.body;
      const token_email = req.token_email;
      const user = await users.findOne({ email });
      const loggedInUser = await users.findOne({ email: token_email });
      if (!user) {
        res.status(404).json("User not found");
        return;
      }
      if (loggedInUser.role == "admin") {
        await users.updateOne({ email }, { $set: { status } });
        res.status(200).json("User status updated");
      }
    });

    app.get("/admin/users", verifyToken, async (req, res) => {
      const user = await users.find().toArray();
      if (!user) {
        res.status(404).json("User not found");
        return;
      }
      res.status(200).json(user);
    });

    //Manager Routes
    app.post("/manager/create-product", verifyToken, async (req, res) => {
      const token_email = req.token_email;
      const loggedInUser = await users.findOne({ email: token_email });
      if (loggedInUser.role == "manager") {
        try {
          const {
            product_name,
            product_description,
            category,
            price,
            available_quantity,
            min_order,
            images,
            payment,
          } = req.body;

        
          const product = {
            product_name,
            product_description,
            category,
            price,
            available_quantity,
            min_order,
            images,
            payment,};
            await products.insertOne(product);
            res.status(201).json("Product Created");
          
        } catch (error) {
          res.status(400).json(error);
        }
      }
    });
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
  }
};

run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
