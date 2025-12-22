const dotenv = require("dotenv");
dotenv.config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId, ServerApiVersion } = require("mongodb");
const Stripe = require("stripe");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const app = express();
const port = process.env.PORT || 3000;

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// middleware
app.use(cookieParser());
app.use(express.json());
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://scholership-c3ad1.firebaseapp.com",
      "https://scholership-c3ad1.web.app",
      process.env.DOMAIN_URL,

      process.env.DOMAIN_URL,
    ],
    credentials: true,
  })
);
const uri = process.env.MONGODB_URL;

const verifyJWTToken = (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) {
    return res.status(401).send({ message: "unauthorized access" });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: "unauthorized access" });
    }
    req.user = decoded;
    next();
  });
};

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();

    const db = client.db("scholership");
    const usersCollection = db.collection("users");
    const scholarshipsCollection = db.collection("scholarships");
    const applicationsCollection = db.collection("applications");
    const reviewsCollection = db.collection("reviews");
    const wishlistsCollection = db.collection("wishlists");

    // middle for admin & moderator
    const verifyAdmin = async (req, res, next) => {
      const tokenEmail = req.user?.email;
      const query = { email: tokenEmail };
      const result = await usersCollection.findOne(query);
      if (!result) {
        return res.status(403).json({ message: "Forbidden access denied" });
      }
      if (result.role === "admin") {
        next();
      }
    };

    const verifyModerator = async (req, res, next) => {
      const tokenEmail = req.user?.email;
      const query = { email: tokenEmail };
      const result = await usersCollection.findOne(query);

      if (!result) {
        return res.status(403).json({ message: "Forbidden access denied" });
      }
      if (result.role === "moderator") {
        next();
      }
    };

    //? users api
    app.get("/users", verifyJWTToken, verifyAdmin, async (req, res) => {
      const { search = "", filter = "", limit = 0, page = 1 } = req.query;
      const skip = (page - 1) * limit;
      const query = {};
      if (search) {
        query.$or = [
          { displayName: { $regex: search, $options: "i" } },
          { email: { $regex: search, $options: "i" } },
        ];
      }

      if (filter) {
        query.role = filter;
      }
      const totalUsers = await usersCollection.countDocuments();
      const result = await usersCollection
        .find(query)
        .limit(Number(limit))
        .skip(Number(skip))
        .toArray();
      res.status(200).json({ users: result, totalUsers });
    });

    app.get("/users/:email/role", verifyJWTToken, async (req, res) => {
      const tokenEmail = req.user?.email;
      const email = req.params.email;
      const query = { email: email };
      if (tokenEmail !== email) {
        return res.status(403).send({
          success: false,
          message: "Forbidden: Access denied. Email mismatch.",
        });
      }
      const result = await usersCollection.findOne(query, {
        $project: { role: 1 },
      });

      res.status(200).send({ role: result?.role } || "student");
    });

    app.post("/users", async (req, res) => {
      const userInfo = req.body;
      userInfo.role = "student";
      userInfo.createdAt = new Date().toISOString();
      const isExits = await usersCollection.findOne({ email: userInfo.email });
      if (isExits) {
        return res.json({ message: "user already exits" });
      }
      const result = await usersCollection.insertOne(userInfo);
      res.status(201).json(result);
    });

    app.patch("/users/:id", verifyJWTToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const updatedDoc = { $set: req.body };
      const result = await usersCollection.updateOne(query, updatedDoc);
      res.status(200).json(result);
    });

    // api for delete user
    app.delete("/users/:id", verifyJWTToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await usersCollection.deleteOne(query);
      res.status(200).json(result);
    });

    //? get JWT Token
    app.post("/getToken", async (req, res) => {
      const userInfo = req.body;
      const token = jwt.sign(userInfo, process.env.JWT_SECRET, {
        expiresIn: "1h",
      });
      res
        .cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        })
        .send({ success: true });
    });

    app.post("/logout", async (req, res) => {
      res
        .clearCookie("token", {
          maxAge: 0,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        })
        .send({ success: true });
    });

    //? scholarships api
    // api for all scholaships
    app.get("/scholarships", async (req, res) => {
      const {
        limit = 0,
        page = 1,
        schCat = "",
        subCat = "",
        loc = "",
        search = "",
        sort = "",
      } = req.query;
      let sortFilter = { applicationFees: 1, scholarshipPostDate: -1 };
      const skip = (page - 1) * limit;
      const query = {};
      if (sort === "asc") {
        sortFilter = { applicationFees: 1 };
      }
      if (sort === "dsc") {
        sortFilter = { applicationFees: -1 };
      }
      if (schCat) {
        query.scholarshipCategory = { $regex: schCat, $options: "i" };
      }
      if (subCat) {
        query.subjectCategory = { $regex: subCat, $options: "i" };
      }
      if (loc) {
        query.universityCountry = { $regex: loc, $options: "i" };
      }

      if (search) {
        query.$or = [
          { scholarshipName: { $regex: search, $options: "i" } },
          { universityName: { $regex: search, $options: "i" } },
          { degree: { $regex: search, $options: "i" } },
        ];
      }
      const totalScholaships = await scholarshipsCollection.countDocuments();
      const result = await scholarshipsCollection
        .find(query)
        .limit(Number(limit))
        .skip(Number(skip))
        .sort(sortFilter)
        .toArray();
      res.status(200).json({ scholarships: result, totalScholaships });
    });

    // api for scholarship details
    app.get("/scholarship/:id", verifyJWTToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await scholarshipsCollection.findOne(query);

      const recomended = await scholarshipsCollection
        .find({
          scholarshipCategory: result.scholarshipCategory,
          _id: { $ne: new ObjectId(id) },
        })
        .limit(3)
        .toArray();
      res.status(200).json({ details: result, recomended });
    });

    // api for scholarship add
    app.post(
      "/add-scholarship",
      verifyJWTToken,
      verifyAdmin,
      async (req, res) => {
        const scholarshipInfo = req.body;
        const result = await scholarshipsCollection.insertOne(scholarshipInfo);
        res.status(201).json(result);
      }
    );

    // api for scholarship edit
    app.patch(
      "/scholarship/:id",
      verifyJWTToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const updatedDoc = { $set: req.body };
        const result = await scholarshipsCollection.updateOne(
          query,
          updatedDoc
        );
        res.status(200).json(result);
      }
    );

    // api for scholarship delete
    app.delete("/scholarship/:id", verifyJWTToken, async (req, res) => {
      const id = req.params.id;
      const { adminEmail } = req.query;
      const tokenEmail = req.user.email;
      const query = { _id: new ObjectId(id) };
      if (adminEmail !== tokenEmail) {
        return res.status(403).json({
          success: false,
          message: "Forbidden: Access denied. Email mismatch.",
        });
      }
      const result = await scholarshipsCollection.deleteOne(query);
      res.status(200).json(result);
    });

    //? Application api
    // api for get applications for moderator
    app.get(
      "/applications",
      verifyJWTToken,
      verifyModerator,
      async (req, res) => {
        const { email } = req.query;
        const tokenEmail = req?.user?.email;
        if (email !== tokenEmail) {
          return res.status(403).json({ message: "access forbidden" });
        }
        const result = await applicationsCollection
          .aggregate([
            {
              $addFields: {
                statusPriority: {
                  $switch: {
                    branches: [
                      {
                        case: { $eq: ["$applicationStatus", "pending"] },
                        then: 0,
                      },
                      {
                        case: { $eq: ["$applicationStatus", "processing"] },
                        then: 1,
                      },
                      {
                        case: { $eq: ["$applicationStatus", "completed"] },
                        then: 2,
                      },
                      {
                        case: { $eq: ["$applicationStatus", "rejected"] },
                        then: 3,
                      },
                    ],
                    default: 99,
                  },
                },
              },
            },
            { $sort: { statusPriority: 1 } },
          ])
          .toArray();

        res.status(200).json(result);
      }
    );

    // api for get applications details
    app.get("/applications/:id", verifyJWTToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await applicationsCollection.findOne(query);
      res.status(200).json(result);
    });

    // api for update application details
    app.patch("/applications/:id", verifyJWTToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const updatedDate = req.body;
      const updatedDoc = { $set: updatedDate };
      const result = await applicationsCollection.updateOne(query, updatedDoc);
      res.status(200).json(result);
    });

    // api for get applications by specific user
    app.get("/applications/:email/byUser", verifyJWTToken, async (req, res) => {
      const email = req.params.email;
      const query = { userEmail: email };
      const result = await applicationsCollection.find(query).toArray();
      res.status(200).json(result);
    });

    // api for update application status
    app.patch(
      "/applications/:id",
      verifyJWTToken,
      verifyModerator,
      async (req, res) => {
        const applicationStatus = req.body;
        const id = req.params.id;

        const query = { _id: new ObjectId(id) };
        const updatedDoc = { $set: applicationStatus };
        const result = await applicationsCollection.updateOne(
          query,
          updatedDoc
        );
        res.status(200).json(result);
      }
    );

    // api for application feedback
    app.patch(
      "/applications/feedback/:id",
      verifyJWTToken,
      verifyModerator,
      async (req, res) => {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const updatedDoc = { $set: req.body };
        const options = { upsert: true };
        const result = await applicationsCollection.updateOne(
          query,
          updatedDoc,
          options
        );
        res.status(200).json(result);
      }
    );

    // api for delete applicatoin
    app.delete("/applications/:id", verifyJWTToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id), applicationStatus: "pending" };
      const result = await applicationsCollection.deleteOne(query);
      res.status(200).json(result);
    });

    //? Reviews api
    // api for get reviews
    app.get("/reviews", verifyJWTToken, verifyModerator, async (req, res) => {
      const result = await reviewsCollection.find().toArray();
      res.status(200).json(result);
    });

    // api for get reviews by user
    app.get("/reviews/user/:email", verifyJWTToken, async (req, res) => {
      const email = req.params.email;
      const query = { email: email };
      const result = await reviewsCollection.find(query).toArray();
      res.status(200).json(result);
    });

    // api for review details
    app.get("/reviews/:id", verifyJWTToken, async (req, res) => {
      const id = req.params.id;
      const query = { scholarshipId: id };
      const result = await reviewsCollection.find(query).toArray();
      res.status(200).json(result);
    });

    // api for post reviews
    app.post("/reviews", verifyJWTToken, async (req, res) => {
      const reviewsInfo = req.body;
      const query = {
        email: reviewsInfo.email,
        scholarshipId: reviewsInfo.scholarshipId,
      };
      const updatedDoc = {
        $set: {
          ...reviewsInfo,
          updatedDate: new Date().toISOString(),
        },
        $setOnInsert: {
          createdAt: new Date().toISOString(),
        },
      };
      const options = { upsert: true };
      const result = await reviewsCollection.updateOne(
        query,
        updatedDoc,
        options
      );

      const ratingResult = await reviewsCollection
        .aggregate([
          {
            $match: { scholarshipId: reviewsInfo.scholarshipId },
          },
          {
            $group: {
              _id: "$scholarshipId",
              averageRating: { $avg: "$rating" },
              totalReview: { $sum: 1 },
            },
          },
        ])
        .toArray();

      if (ratingResult.length > 0) {
        const { averageRating, totalReview } = ratingResult[0];
        const roundedRating = Math.round(averageRating / 5) * 5;
        await scholarshipsCollection.updateOne(
          {
            _id: new ObjectId(reviewsInfo.scholarshipId),
          },
          {
            $set: {
              ratings: roundedRating,
              totalReview: totalReview,
            },
          }
        );
      }

      res.status(200).json(result);
    });

    // api for delete reviews
    app.delete("/reviews/:id", verifyJWTToken, async (req, res) => {
      const id = req.params.id;
      const result = await reviewsCollection.deleteOne({
        _id: new ObjectId(id),
      });
      res.status(200).json(result);
    });

    //? Analytics page api
    // api for admin analytics
    app.get("/analytics", async (req, res) => {
      const totalScholaships = await scholarshipsCollection.countDocuments();
      const totalUsers = await usersCollection.countDocuments();
      const totalFessData = await applicationsCollection
        .aggregate([
          {
            $group: {
              _id: null,
              totalFees: { $sum: "$amountPaid" },
            },
          },
          {
            $project: {
              _id: 0,
              totalFees: 1,
            },
          },
        ])
        .toArray();
      const totalFees = totalFessData[0]?.totalFees || 0;

      const appsByCategory = await applicationsCollection
        .aggregate([
          {
            $group: {
              _id: "$scholarshipCategory",
              count: { $sum: 1 },
            },
          },
          {
            $project: {
              _id: 0,
              category: "$_id",
              count: 1,
            },
          },
        ])
        .sort({ count: -1 })
        .toArray();

      const appsByUniversity = await applicationsCollection
        .aggregate([
          {
            $group: {
              _id: "$universityName",
              count: { $sum: 1 },
            },
          },
          {
            $project: {
              _id: 0,
              universityName: "$_id",
              count: 1,
            },
          },
        ])
        .sort({ count: -1 })
        .toArray();

      res.send({
        totalScholaships,
        totalUsers,
        totalFees,
        appsByCategory,
        appsByUniversity,
      });
    });

    // wishlist api
    // api for get wishlists
    app.get("/wishlists", verifyJWTToken, async (req, res) => {
      try {
        const email = req.query.email;

        // Security check: Ensure user can only access their own data
        if (req.user.email !== email) {
          return res.status(403).send({ message: "Forbidden access" });
        }

        const result = await wishlistsCollection
          .aggregate([
            // 1. Match wishlist items for this user
            {
              $match: { userEmail: email },
            },
            // 2. Convert scholarshipId string to ObjectId (if stored as string in wishlist)
            {
              $addFields: {
                scholarshipObjectId: { $toObjectId: "$scholarshipId" },
              },
            },
            // 3. Lookup (Join) with scholarships collection
            {
              $lookup: {
                from: "scholarships",
                localField: "scholarshipObjectId",
                foreignField: "_id",
                as: "scholarshipDetails",
              },
            },
            // 4. Unwind the array (because lookup returns an array)
            {
              $unwind: "$scholarshipDetails",
            },
            // 5. Project (Select) the fields you want to send to frontend
            {
              $project: {
                _id: 1, // Wishlist ID (needed for delete)
                scholarshipId: 1,
                userEmail: 1,
                // Fields from the joined scholarship collection
                universityName: "$scholarshipDetails.universityName",
                scholarshipName: "$scholarshipDetails.scholarshipName",
                universityImage: "$scholarshipDetails.universityImage",
                scholarshipCategory: "$scholarshipDetails.scholarshipCategory",
                degree: "$scholarshipDetails.degree",
                applicationFees: "$scholarshipDetails.applicationFees",
                serviceCharge: "$scholarshipDetails.serviceCharge",
                universityLocation: {
                  $concat: [
                    "$scholarshipDetails.universityCity",
                    ", ",
                    "$scholarshipDetails.universityCountry",
                  ],
                },
              },
            },
          ])
          .toArray();

        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // api for get wishlist status
    app.get(
      "/wishlists/check/:scholarshipId",
      verifyJWTToken,
      async (req, res) => {
        const { scholarshipId } = req.params;
        const { email } = req.query;
        const result = await wishlistsCollection.findOne({
          scholarshipId,
          userEmail: email,
        });

        if (result) {
          // Document found
          res.send({ isSaved: true, id: result._id });
        } else {
          // Document NOT found - Return null ID
          res.send({ isSaved: false, id: null });
        }
      }
    );

    // api for delete wishlist
    app.delete("/wishlists/:id", verifyJWTToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await wishlistsCollection.deleteOne(query);
      res.status(200).json(result);
    });

    // api for add wishlist
    app.post("/wishlists", verifyJWTToken, async (req, res) => {
      const wishlistInfo = req.body;
      wishlistInfo.createdAt = new Date().toISOString();
      const query = {
        scholarshipId: wishlistInfo?.scholarshipId,
        userEmail: wishlistInfo?.userEmail,
      };
      const isExits = await wishlistsCollection.findOne(query);
      if (isExits) {
        return res
          .status(200)
          .json({ success: false, message: "already in wishlist" });
      }
      const result = await wishlistsCollection.insertOne(wishlistInfo);
      res.status(201).json(result);
    });

    //! payment api
    // api for create checkout session with add application info
    app.post("/create-checkout-session", verifyJWTToken, async (req, res) => {
      const {
        scholarshipId,
        scholarshipName,
        universityImage,
        userName,
        universityName,
        universityCity,
        universityCountry,
        scholarshipCategory,
        subjectCategory,
        degree,
        applicationFees,
        serviceCharge,
        totalPrice,
        phone,
        photoURL,
        address,
        gender,
        studyGap,
        sscResult,
        hscResult,
      } = req.body;

      const tokenEmail = req.user.email;
      if (req.body.userEmail !== tokenEmail) {
        return res
          .status(403)
          .send({ message: "Forbidden: You can only apply for yourself" });
      }

      const userEmail = tokenEmail;

      const isScholarshipExits = await scholarshipsCollection.findOne({
        _id: new ObjectId(scholarshipId),
      });

      if (!isScholarshipExits) {
        return res.status(404).json({ message: "Scholarship not found" });
      }

      const isExitsApplication = await applicationsCollection.findOne({
        scholarshipId: scholarshipId,
        userEmail: userEmail,
      });

      if (isExitsApplication) {
        // if user unpaid then show this message
        if (isExitsApplication.paymentStatus === "unpaid") {
          return res.json({
            message:
              "You have a pending application. Please pay from your dashboard.",
            insertedId: null,
          });
        }
        // else user already paid
        else {
          return res.json({
            message:
              "You have already completed the application for this scholarship.",
            insertedId: null,
          });
        }
      }

      // if user not apply then insert data
      const applicationInfo = {
        phone,
        photoURL,
        address,
        gender,
        studyGap,
        sscResult,
        hscResult,
        scholarshipId,
        userEmail,
        userName,
        universityName,
        universityCity,
        universityImage,
        scholarshipName,
        universityCountry,
        scholarshipCategory,
        subjectCategory,
        degree,
        applicationFees,
        serviceCharge,
        applicationStatus: "pending",
        paymentStatus: "unpaid",
        applicationDate: new Date().toISOString(),
      };

      const applicatioinResult = await applicationsCollection.insertOne(
        applicationInfo
      );

      // Create Stripe Session
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: {
                name: `Application for: ${scholarshipName}`,
                description: `University: ${universityName}`,
                images: [universityImage],
              },
              unit_amount: Math.round(totalPrice * 100),
            },
            quantity: 1,
          },
        ],
        customer_email: userEmail,
        mode: "payment",
        metadata: {
          applicationId: applicatioinResult.insertedId.toString(),
          scholarshipId: scholarshipId,
          userEmail: userEmail,
        },
        success_url: `${process.env.DOMAIN_URL}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.DOMAIN_URL}/payment/fail?scholarshipName=${scholarshipName}`,
      });

      res.json({ url: session.url });
    });

    // api for retry payment from dashboard
    app.post("/retry-payment/:id", verifyJWTToken, async (req, res) => {
      const id = req.params.id;
      const tokenEmail = req.user.email;

      try {
        const query = { _id: new ObjectId(id) };
        const application = await applicationsCollection.findOne(query);

        // 1. Check if application exists
        if (!application) {
          return res.status(404).send({ message: "Application not found" });
        }

        // 2. Verify user ownership
        if (application.userEmail !== tokenEmail) {
          return res.status(403).send({ message: "Forbidden Access" });
        }

        // 4. Create Stripe Session
        // Note: We use the data already saved in the database
        const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          line_items: [
            {
              price_data: {
                currency: "usd",
                product_data: {
                  name: `Application for: ${application.scholarshipName}`,
                  description: `University: ${application.universityName}`,
                  images: [application.universityImage],
                },
                unit_amount: Math.round(
                  (application.applicationFees + application.serviceCharge) *
                    100
                ),
              },
              quantity: 1,
            },
          ],
          customer_email: application.userEmail,
          mode: "payment",
          metadata: {
            applicationId: id,
            scholarshipId: application.scholarshipId,
            userEmail: application.userEmail,
          },
          // Redirect URLs
          success_url: `${process.env.DOMAIN_URL}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${process.env.DOMAIN_URL}/payment/fail?scholarshipName=${application.scholarshipName}`,
        });

        res.json({ url: session.url });
      } catch (error) {
        // console.error("Payment Error:", error);
        res.status(500).send({ message: "Internal Server Error" });
      }
    });

    // api for check payment status and update payment status
    app.patch("/payment/success", verifyJWTToken, async (req, res) => {
      const { sessionId } = req.body;

      try {
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        const { amount_total, metadata, payment_intent, payment_status } =
          session;

        const tokenEmail = req.user.email;

        if (!metadata || !metadata.applicationId || !metadata.userEmail) {
          return res
            .status(400)
            .send({ success: false, message: "Invalid Session Metadata" });
        }

        const { applicationId, userEmail, scholarshipId } = metadata;

        if (tokenEmail !== userEmail) {
          return res.status(403).send({
            success: false,
            message: "Forbidden: Access denied. Email mismatch.",
          });
        }

        if (payment_status === "paid") {
          const query = { _id: new ObjectId(applicationId) };

          const updatedDoc = {
            $set: {
              paymentStatus: payment_status,
              transactionId: payment_intent,
              amountPaid: amount_total / 100,
            },
          };

          const applicationUpdate = await applicationsCollection.updateOne(
            query,
            updatedDoc
          );

          if (applicationUpdate.modifiedCount) {
            await scholarshipsCollection.updateOne(
              { _id: new ObjectId(scholarshipId) },
              {
                $inc: {
                  applicantNumber: 1,
                },
              }
            );

            const applicationInfo = await applicationsCollection.findOne(query);

            return res.status(200).json({
              success: true,
              data: applicationInfo,
              message: "Payment confirmed",
            });
          } else {
            // Handle case where it wasn't modified (maybe already paid)
            // when user reload or again come to the page
            const applicationInfo = await applicationsCollection.findOne(query);

            if (applicationInfo && applicationInfo.paymentStatus === "paid") {
              return res.status(200).json({
                success: true,
                message: "Already Paid",
                data: applicationInfo,
              });
            }
            return res
              .status(400)
              .send({ success: false, message: "Update failed" });
          }
        } else {
          return res
            .status(400)
            .send({ success: false, message: "Payment not completed" });
        }
      } catch (error) {
        console.error("Payment Error:", error);
        return res
          .status(500)
          .send({ success: false, message: "Internal Server Error" });
      }
    });

    // await client.db("admin").command({ ping: 1 });
    // console.log(
    //   "Pinged your deployment. You successfully connected to MongoDB!"
    // );
  } finally {
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("SchollerStream server is running!");
});

app.listen(port, () => {
  console.log(`SchollerStream app listening on port ${port}`);
});
