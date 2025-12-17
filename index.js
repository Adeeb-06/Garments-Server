import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import admin from "firebase-admin";
dotenv.config();

import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8"
);
const serviceAccount = JSON.parse(decoded);

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  cors({
    origin: ["http://localhost:5173", "https://garment-627fe.web.app"],
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
    const db = client.db("garments");
    const users = db.collection("users");
    const products = db.collection("products");
    const orders = db.collection("orders");
    const tracking = db.collection("tracking");

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
      const { status, reason, feedback } = req.body;
      const token_email = req.token_email;
      const user = await users.findOne({ email });
      const loggedInUser = await users.findOne({ email: token_email });
      if (!user) {
        res.status(404).json("User not found");
        return;
      }
      if (loggedInUser.role == "admin") {
        await users.updateOne(
          { email },
          { $set: { status, reason, feedback } }
        );
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

    app.get("/admin/all-orders", verifyToken, async (req, res) => {
      const token_email = req.token_email;
      const loggedInUser = await users.findOne({ email: token_email });
      if (loggedInUser.role == "admin") {
        try {
          const page = parseInt(req.query.page) || 1;
          const limit = parseInt(req.query.limit) || 10;
          const skip = (page - 1) * limit;

          const orderData = await orders
            .find(
              {},
              {
                projection: {
                  _id: 1,
                  product_name: 1,
                  qty: 1,
                  email: 1,
                  status: 1,
                },
                sort: { createdAt: -1 },
              }
            )
            .skip(skip)
            .limit(limit)
            .toArray();

          const totalCount = await orders.countDocuments({});

          res.status(200).json({
            data: orderData,
            total: totalCount,
            page,
            totalPages: Math.ceil(totalCount / limit),
          });
        } catch (error) {
          res.status(400).json(error.message);
        }
      }
    });

    app.patch("/admin/product-status/:id", verifyToken, async (req, res) => {
      const token_email = req.token_email;
      const loggedInUser = await users.findOne({ email: token_email });
      if (loggedInUser.role == "admin") {
        try {
          const id = req.params.id;
          const { onHomePage } = req.body;
          const product = await products.findOne({ _id: new ObjectId(id) });
          if (!product) {
            res.status(404).json("Product not found");
            return;
          }
          await products.updateOne(
            { _id: new ObjectId(id) },
            { $set: { onHomePage } }
          );
          res.status(200).json("Product status updated");
        } catch (error) {
          res.status(400).json(error);
        }
      }
    });

    app.get("/admin/products", verifyToken, async (req, res) => {
      const token_email = req.token_email;
      const loggedInUser = await users.findOne({ email: token_email });
      if (loggedInUser.role == "admin") {
        try {
          const productsData = await products
            .find(
              {},
              {
                projection: {
                  images: 1,
                  product_name: 1,
                  price: 1,
                  createdBy: 1,
                  category: 1,
                  payment: 1,
                  onHomePage: 1,
                },
              }
            )
            .toArray();
          res.status(200).json(productsData);
        } catch (error) {
          res.status(400).json(error.message);
        }
      }
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
            payment,
            onHomePage: false,
            createdBy: token_email,
            createdAt: new Date(),
          };
          await products.insertOne(product);
          res.status(201).json("Product Created");
        } catch (error) {
          res.status(400).json(error);
        }
      }
    });

    app.delete("/delete-product/:id", verifyToken, async (req, res) => {
      const token_email = req.token_email;
      const loggedInUser = await users.findOne({ email: token_email });
      if (loggedInUser.role === "manager" || loggedInUser.role === "admin") {
        try {
          const id = req.params.id;
          const product = await products.findOne({ _id: new ObjectId(id) });
          if (!product) {
            res.status(404).json("Product not found");
            return;
          }
          await products.findOneAndDelete({ _id: new ObjectId(id) });
          res.status(200).json({ message: "Product deleted" });
        } catch (error) {
          res.status(400).json(error);
        }
      }
    });

    app.get("/products-management", verifyToken, async (req, res) => {
      const token_email = req.token_email;
      const loggedInUser = await users.findOne({ email: token_email });
      if (loggedInUser.role === "manager" || loggedInUser.role === "admin") {
        try {
          const productsData = await products
            .find(
              {},
              {
                projection: {
                  _id: 1,
                  product_name: 1,
                  price: 1,
                  images: 1,
                  payment: 1,
                  onHomePage: 1,
                },
              }
            )
            .toArray();
          res.status(200).json(productsData);
        } catch (error) {
          res.status(400).json(error.message);
        }
      } else {
        res.status(401).json("Unauthorized: No Access");
      }
    });

    app.get("/product/:id", verifyToken, async (req, res) => {
      const token_email = req.token_email;
      const loggedInUser = await users.findOne({ email: token_email });
      if (loggedInUser.role == "manager" || "admin") {
        try {
          const id = req.params.id;
          const product = await products.findOne({ _id: new ObjectId(id) });
          if (!product) {
            res.status(404).json("Product not found");
            return;
          }
          res.status(200).json(product);
        } catch (error) {
          res.status(400).json(error);
        }
      } else {
        res.status(401).json("Unauthorized: No Access");
      }
    });

    app.put("/update-product/:id", verifyToken, async (req, res) => {
      const token_email = req.token_email;
      const loggedInUser = await users.findOne({ email: token_email });

      if (loggedInUser.role === "manager" || loggedInUser.role === "admin") {
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

          const id = req.params.id;
          const product = {
            product_name,
            product_description,
            category,
            price,
            available_quantity,
            min_order,
            images,
            payment,
            onHomePage: false,
          };

          await products.updateOne(
            { _id: new ObjectId(id) },
            { $set: product }
          );
          res.status(200).json("Product Updated");
        } catch (error) {
          res.status(400).json(error);
        }
      } else {
        res.status(401).json("Unauthorized: No Access");
      }
    });

    app.get("/products", async (req, res) => {
      try {
        const token_email = req.token_email;
        const productsData = await products
          .find({ createdBy: token_email })
          .toArray();
        res.status(200).json(productsData);
      } catch (error) {
        res.status(400).json(error.message);
      }
    });

    app.get("/manager/pending-orders", verifyToken, async (req, res) => {
      const token_email = req.token_email;
      const loggedInUser = await users.findOne({ email: token_email });
      if (loggedInUser.role == "manager") {
        try {
          const pendingOrdersData = await orders
            .find(
              {
                status: { $in: ["pending", "rejected"] },
                productManager: token_email,
              },
              {
                projection: {
                  _id: 1,
                  product_name: 1,
                  qty: 1,
                  email: 1,
                  status: 1,
                  createdAt: 1,
                },
              }
            )
            .toArray();
          res.status(200).json(pendingOrdersData);
        } catch (error) {
          res.status(400).json(error.message);
        }
      }
    });

    app.patch("/manager/approve-order/:id", verifyToken, async (req, res) => {
      const token_email = req.token_email;
      const loggedInUser = await users.findOne({ email: token_email });
      if (loggedInUser.role == "manager") {
        try {
          const id = req.params.id;
          const order = await orders.findOne({ _id: new ObjectId(id) });
          if (!order) {
            res.status(404).json("Order not found");
            return;
          }
          await orders.updateOne(
            { _id: new ObjectId(id) },
            { $set: { status: "approved", approvedDate: new Date() } }
          );

          res.status(200).json("Order Approved");
        } catch (error) {
          res.status(400).json(error);
        }
      }
    });

    app.patch("/manager/reject-order/:id", verifyToken, async (req, res) => {
      const token_email = req.token_email;
      const loggedInUser = await users.findOne({ email: token_email });
      if (loggedInUser.role == "manager") {
        try {
          const id = req.params.id;
          const order = await orders.findOne({ _id: new ObjectId(id) });
          if (!order) {
            res.status(404).json("Order not found");
            return;
          }
          await orders.updateOne(
            { _id: new ObjectId(id) },
            { $set: { status: "rejected" } }
          );

          res.status(200).json("Order Rejected");
        } catch (error) {
          res.status(400).json(error);
        }
      }
    });

    app.get("/manager/approved-orders", verifyToken, async (req, res) => {
      const token_email = req.token_email;
      const loggedInUser = await users.findOne({ email: token_email });
      if (loggedInUser.role == "manager") {
        try {
          const approveOrdersData = await orders
            .find(
              { status: "approved", productManager: token_email },
              {
                projection: {
                  _id: 1,
                  product_name: 1,
                  qty: 1,
                  email: 1,
                  approvedDate: 1,
                  tracking: 1,
                },
              }
            )
            .toArray();
          res.status(200).json(approveOrdersData);
        } catch (error) {
          res.status(400).json(error.message);
        }
      }
    });

    app.patch("/tracking-order/:id", verifyToken, async (req, res) => {
      const token_email = req.token_email;
      const loggedInUser = await users.findOne({ email: token_email });

      if (loggedInUser.role !== "manager") {
        return res.status(403).json("Forbidden");
      }

      try {
        const id = req.params.id;
        const { status, location } = req.body;

        const order = await orders.findOne({ _id: new ObjectId(id) });
        if (!order) {
          return res.status(404).json("Order not found");
        }

        if (status === "Shipped") {
          await orders.updateOne(
            { _id: new ObjectId(id) },
            {
              $push: {
                tracking: {
                  status,
                  location,
                  createdAt: new Date(),
                  paymentStatus: "paid",
                },
              },
            }
          );
        }
        await orders.updateOne(
          { _id: new ObjectId(id) },
          {
            $push: {
              tracking: {
                status,
                location,
                createdAt: new Date(),
              },
            },
          }
        );

        res.status(200).json("Tracking updated");
      } catch (error) {
        res.status(400).json(error.message);
      }
    });

    // Buyer Routes
    app.get("/products-homepage", async (req, res) => {
      try {
        const productsData = await products
          .find(
            {
              onHomePage: true,
            },
            {
              projection: {
                images: 1,
                product_name: 1,
                product_description: 1,
                category: 1,
                price: 1,
                available_quantity: 1,
              },
            }
          )
          .limit(6)
          .toArray();
        res.status(200).json(productsData);
      } catch (error) {
        res.status(400).json(error.message);
      }
    });

    app.post("/order/:id", verifyToken, async (req, res) => {
      const token_email = req.token_email;
      const loggedInUser = await users.findOne({ email: token_email });
      if (loggedInUser.status === "approve") {
        try {
          const {
            product_id,
            product_name,
            qty,
            firstName,
            lastName,
            email,
            deliveryAddress,
            orderPrice,
            additionalNotes,
            contactNumber,
            paymentMethod,
          } = req.body;
          const product = await products.findOne({
            _id: new ObjectId(product_id),
          });
          if (!product) {
            res.status(404).json("Product not found");
            return;
          }
          const orderData = {
            product_id,
            product_name,
            qty,
            firstName,
            lastName,
            email,
            deliveryAddress,
            orderPrice,
            additionalNotes,
            paymentStatus: "pending",
            contactNumber,
            paymentMethod,
            status: "pending",
            productManager: product.createdBy,
            createdAt: new Date(),
          };
          await orders.insertOne(orderData);

          await products.updateOne(
            { _id: new ObjectId(product_id) },
            { $set: { available_quantity: product.available_quantity - qty } }
          );

          res.status(201).json(orderData, "Order Created");
        } catch (error) {
          res.status(400).json(error.message);
        }
      } else {
        res.status(401).json("Account not approved");
      }
    });

    app.get("/order/:id", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const orderData = await orders.findOne({ _id: new ObjectId(id) });
        res.status(200).json(orderData);
      } catch (error) {
        res.status(400).json(error);
      }
    });

    app.post("/stripe-payment", async (req, res) => {
      const paymentInfo = req.body;
      const amount = parseInt(paymentInfo.price) * 100;
      const session = await stripe.checkout.sessions.create({
        line_items: [
          {
            price_data: {
              currency: "usd",
              unit_amount: amount,
              product_data: {
                name: paymentInfo.product_name,
              },
            },
            quantity: 1,
          },
        ],
        mode: "payment",
        metadata: {
          productId: paymentInfo.product_id,
          orderId: paymentInfo.order_id,
        },
        customer_email: paymentInfo.email,
        success_url: `${process.env.YOUR_DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.YOUR_DOMAIN}/payment-cancel`,
      });
      res.send({ url: session.url });
    });

    app.patch("/payment-success", async (req, res) => {
      const session_id = req.query.session_id;

      const session = await stripe.checkout.sessions.retrieve(session_id);

      console.log(session.amount_subtotal);
      if (session.payment_status === "paid") {
        const orderID = session.metadata.orderId;
        const order = await orders.findOne({ _id: new ObjectId(orderID) });
        if (!order) {
          res.status(404).json("Order not found");
          return;
        }
        if (order.paymentStatus === "pending") {
          const result = await orders.updateOne(
            { _id: new ObjectId(orderID) },
            { $set: { paymentStatus: "paid" } }
          );
          if (result.acknowledged) {
            res.status(200).json(session, "Payment Successful");
          }
        }
      }
      res.send(session, "false");
    });

    app.get("/buyer/all-orders/:email", verifyToken, async (req, res) => {
      const buyerEmail = decodeURIComponent(req.params.email);
      const user = await users.findOne({ email: buyerEmail });
      if (!user) {
        res.status(404).json("User not found");
        return;
      }
      try {
        const ordersData = await orders
          .find(
            { email: buyerEmail },
            {
              projection: {
                product_name: 1,
                status: 1,
                paymentStatus: 1,
                orderPrice: 1,
                email: 1,
                product_id: 1,
                _id: 1,
                qty: 1,
              },
            }
          )
          .toArray();
        res.status(200).json(ordersData);
      } catch (error) {
        res.status(400).json(error.message);
      }
    });

    app.get("/all-products", async (req, res) => {
      try {
        const productsData = await products
          .find(
            {},
            {
              projection: {
                images: 1,
                product_name: 1,
                product_description: 1,
                category: 1,
                price: 1,
                available_quantity: 1,
              },
            }
          )
          .toArray();
        res.status(200).json(productsData);
      } catch (error) {
        res.status(400).json(error.message);
      }
    });

    app.delete("/delete-order/:id", verifyToken, async (req, res) => {
      const token_email = req.token_email;
      const loggedInUser = await users.findOne({ email: token_email });
      if (loggedInUser.role === "buyer") {
        try {
          const id = req.params.id;
          const order = await orders.findOne({ _id: new ObjectId(id) });
          if (!order) {
            res.status(404).json("Order not found");
            return;
          }
          if (order.status === "approved") {
            res.status(400).json("Order already approved");
            return;
          }
          await orders.findOneAndDelete({ _id: new ObjectId(id) });
          res.status(200).json({ message: "Order deleted" });
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
