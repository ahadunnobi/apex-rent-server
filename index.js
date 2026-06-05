const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const { createRemoteJWKSet, jwtVerify, decodeJwt } = require("jose-cjs");

dotenv.config();

const uri = process.env.MONGODB;
/** Next.js URLs where Better Auth issues JWTs (NOT the Express server URL) */
const AUTH_BASE_URLS = [
  process.env.AUTH_BASE_URL,
  process.env.CLIENT_URL,
  "http://localhost:3000",
  "https://apex-renti.vercel.app",
]
  .filter(Boolean)
  .map((u) => u.replace(/\/$/, ""))
  .filter((u, i, arr) => arr.indexOf(u) === i);

const PORT = process.env.PORT || 5000;
const INTERNAL_API_SECRET = process.env.INTERNAL_API_SECRET;

const app = express();

app.use(
  cors({
    origin: [...AUTH_BASE_URLS, "http://localhost:3000"].filter(
      (v, i, a) => a.indexOf(v) === i
    ),
    credentials: true,
  })
);
app.use(express.json());

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let carsCollection;
let bookingsCollection;
let usersCollection;

function trustInternalProxy(req, res, next) {
  if (!INTERNAL_API_SECRET) return false;

  const secret = req.headers["x-internal-secret"];
  if (secret !== INTERNAL_API_SECRET) return false;

  const email = req.headers["x-user-email"];
  if (!email) {
    res.status(401).json({ message: "Unauthorized. Please log in." });
    return true;
  }

  req.user = {
    email,
    name: req.headers["x-user-name"] || email.split("@")[0],
    id: req.headers["x-user-id"] || "",
  };
  next();
  return true;
}

async function trustBearerJwt(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) return false;

  const token = authHeader.split(" ")[1];
  if (!token) return false;

  let decoded;
  try {
    decoded = decodeJwt(token);
  } catch {
    return false;
  }

  const iss =
    typeof decoded.iss === "string" ? decoded.iss.replace(/\/$/, "") : null;
  const issuersToTry = iss
    ? [iss, ...AUTH_BASE_URLS.filter((u) => u !== iss)]
    : [...AUTH_BASE_URLS];

  let lastError = null;

  for (const baseUrl of issuersToTry) {
    try {
      const jwks = createRemoteJWKSet(new URL(`${baseUrl}/api/auth/jwks`));
      const audience = decoded.aud
        ? Array.isArray(decoded.aud)
          ? decoded.aud
          : [decoded.aud]
        : [baseUrl];

      const { payload } = await jwtVerify(token, jwks, {
        issuer: baseUrl,
        audience,
      });

      let email = payload.email;

      if (!email && payload.sub && usersCollection) {
        const dbUser = await usersCollection.findOne({ id: payload.sub });
        email = dbUser?.email;
      }

      if (!email) {
        res.status(403).json({
          message: "Token missing user email. Please log out and log in again.",
        });
        return true;
      }

      req.user = {
        email,
        name: payload.name || email.split("@")[0],
        id: payload.sub,
      };
      next();
      return true;
    } catch (error) {
      lastError = error;
    }
  }

  console.error("JWT verify failed:", lastError?.message);
  return false;
}

const verifyToken = async (req, res, next) => {
  if (trustInternalProxy(req, res, next)) return;
  if (await trustBearerJwt(req, res, next)) return;

  return res.status(403).json({
    message:
      "Forbidden. Log out and log in again. Ensure INTERNAL_API_SECRET matches on frontend and API server.",
  });
};

function isCarUnavailable(car) {
  return car.availability === "Unavailable" || car.availability_status === false;
}

// --- CARS ---

app.get("/cars", async (req, res) => {
  try {
    const { search, type } = req.query;
    const conditions = [];

    if (search) {
      conditions.push({
        $or: [
          { name: { $regex: search, $options: "i" } },
          { car_name: { $regex: search, $options: "i" } },
        ],
      });
    }

    if (type) {
      conditions.push({
        $or: [{ type }, { car_type: type }],
      });
    }

    const query = conditions.length ? { $and: conditions } : {};
    const result = await carsCollection.find(query).sort({ createdAt: -1 }).toArray();
    res.json(result);
  } catch {
    res.status(500).json({ message: "Failed to fetch cars" });
  }
});

app.get("/cars/my", verifyToken, async (req, res) => {
  try {
    const result = await carsCollection
      .find({
        $or: [{ ownerEmail: req.user.email }, { addedBy: req.user.email }],
      })
      .sort({ createdAt: -1 })
      .toArray();
    res.json(result);
  } catch {
    res.status(500).json({ message: "Failed to fetch your cars" });
  }
});

app.get("/cars/:id", async (req, res) => {
  try {
    const result = await carsCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!result) return res.status(404).json({ message: "Car not found" });
    res.json(result);
  } catch {
    res.status(500).json({ message: "Failed to fetch car" });
  }
});

app.post("/cars", verifyToken, async (req, res) => {
  try {
    const carData = req.body;
    const newCar = {
      ...carData,
      ownerEmail: req.user.email,
      addedBy: req.user.email,
      booking_count: 0,
      createdAt: new Date(),
    };
    delete newCar._id;
    const result = await carsCollection.insertOne(newCar);
    res.json(result);
  } catch {
    res.status(500).json({ message: "Failed to add car" });
  }
});

app.put("/cars/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const car = await carsCollection.findOne({ _id: new ObjectId(id) });
    if (!car) return res.status(404).json({ message: "Car not found" });

    const owner = car.ownerEmail || car.addedBy;
    if (owner !== req.user.email) {
      return res.status(403).json({ message: "You can only update your own listings." });
    }

    const updatedCar = { ...req.body };
    delete updatedCar._id;
    delete updatedCar.ownerEmail;

    const result = await carsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedCar }
    );
    res.json(result);
  } catch {
    res.status(500).json({ message: "Failed to update car" });
  }
});

app.delete("/cars/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const car = await carsCollection.findOne({ _id: new ObjectId(id) });
    if (!car) return res.status(404).json({ message: "Car not found" });

    const owner = car.ownerEmail || car.addedBy;
    if (owner !== req.user.email) {
      return res.status(403).json({ message: "You can only delete your own listings." });
    }

    const result = await carsCollection.deleteOne({ _id: new ObjectId(id) });
    res.json(result);
  } catch {
    res.status(500).json({ message: "Failed to delete car" });
  }
});

// --- BOOKINGS ---

app.get("/bookings/my", verifyToken, async (req, res) => {
  try {
    const result = await bookingsCollection
      .find({ userEmail: req.user.email })
      .sort({ bookingDate: -1 })
      .toArray();
    res.json(result);
  } catch {
    res.status(500).json({ message: "Failed to fetch bookings" });
  }
});

app.post("/bookings", verifyToken, async (req, res) => {
  try {
    const { carId, driverNeeded, specialNote } = req.body;
    if (!carId) {
      return res.status(400).json({ message: "Car ID is required." });
    }

    const car = await carsCollection.findOne({ _id: new ObjectId(carId) });
    if (!car) return res.status(404).json({ message: "Car not found" });
    if (isCarUnavailable(car)) {
      return res.status(400).json({ message: "This car is currently unavailable." });
    }

    const dailyPrice = Number(car.daily_rent_price || car.price || 0);
    const booking = {
      carId: car._id.toString(),
      carName: car.car_name || car.name,
      carImage: car.image_url || car.image,
      carType: car.car_type || car.type,
      location: car.pickup_location || car.pickupLocation || car.location,
      dailyPrice,
      totalPrice: dailyPrice,
      driverNeeded: driverNeeded || "No",
      specialNote: specialNote || "",
      userEmail: req.user.email,
      userName: req.user.name || req.user.email?.split("@")[0],
      bookingDate: new Date(),
      status: "Confirmed",
    };

    const result = await bookingsCollection.insertOne(booking);

    await carsCollection.updateOne(
      { _id: new ObjectId(carId) },
      { $inc: { booking_count: 1 } }
    );

    res.json({ ...booking, _id: result.insertedId });
  } catch (error) {
    console.error("Booking error:", error);
    res.status(500).json({ message: "Failed to create booking" });
  }
});

app.delete("/bookings/:id", verifyToken, async (req, res) => {
  try {
    const booking = await bookingsCollection.findOne({
      _id: new ObjectId(req.params.id),
      userEmail: req.user.email,
    });
    if (!booking) return res.status(404).json({ message: "Booking not found" });
    await bookingsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ success: true });
  } catch {
    res.status(500).json({ message: "Failed to cancel booking" });
  }
});

app.get("/", (req, res) => {
  res.send("Apex Rent Server is running!");
});

async function start() {
  await client.connect();
  const db = client.db("apexRentDB");
  carsCollection = db.collection("cars");
  bookingsCollection = db.collection("bookings");
  usersCollection = db.collection("user");
  console.log("Connected to MongoDB — Apex Rent API ready");

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

start().catch(console.error);
