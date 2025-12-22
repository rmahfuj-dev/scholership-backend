<div align="center">

  <img src="https://via.placeholder.com/150" alt="Logo" width="100" height="100" />
  
  # 🎓 ScholarStream API
  ### The Backend Service for ScholarStream

  <p>
    This is the secure REST API powering the ScholarStream platform. It handles authentication, payment processing via Stripe, database management, and complex aggregation queries for analytics.
  </p>

  <!-- Badges -->
  <p>
    <img src="https://img.shields.io/badge/Node.js-18+-green?style=flat-square&logo=nodedotjs" />
    <img src="https://img.shields.io/badge/Express-5.2-black?style=flat-square&logo=express" />
    <img src="https://img.shields.io/badge/MongoDB-Native-47A248?style=flat-square&logo=mongodb" />
    <img src="https://img.shields.io/badge/JWT-Auth-pink?style=flat-square&logo=jsonwebtokens" />
    <img src="https://img.shields.io/badge/Stripe-API-635BFF?style=flat-square&logo=stripe" />
  </p>

  <!-- Quick Links -->
  <p>
    <a href="https://scholarstream-web.netlify.app"><strong>🔗 View Live Site</strong></a> •
    <a href="https://github.com/rmahfuj-dev/scholership-frontend"><strong>📂 Client Repo</strong></a> •
    <a href="https://github.com/rmahfuj-dev/scholership-backend"><strong>📂 Server Repo</strong></a>
  </p>
</div>

---

## 📡 API Overview

The ScholarStream API is built with **Node.js** and **Express**, utilizing the **MongoDB Native Driver** for high-performance database interactions. It serves as the bridge between the React frontend and the database, ensuring data integrity and security.

---

## ⚙️ Key Backend Features

### 🔐 Authentication & Security

- **JWT (JSON Web Tokens):** Secure token generation for user sessions.
- **HttpOnly Cookies:** Tokens are stored in secure cookies to prevent XSS attacks.
- **Role-Based Middleware:** Custom middleware (`verifyToken`, `verifyAdmin`, `verifyModerator`) to restrict access to specific endpoints.
- **CORS Config:** Securely allows requests only from the production frontend.

### 💳 Payment Integration

- **Stripe Payment Intents:** Generates client secrets for secure frontend transactions.
- **Revenue Calculation:** Backend logic to track and aggregate total application fees collected.

### 📊 Data Management

- **Aggregation Pipelines:** Complex MongoDB queries to calculate analytics (Total Users, Category Counts, etc.).
- **CRUD Operations:** Optimized endpoints for managing Scholarships, Applications, and Reviews.

---

## 🧱 Tech Stack

| Type               | Technologies                        |
| :----------------- | :---------------------------------- |
| **Runtime**        | Node.js                             |
| **Framework**      | Express.js (v5.2.1)                 |
| **Database**       | MongoDB Native Driver (v7.0.0)      |
| **Authentication** | JSON Web Token (JWT), Cookie-Parser |
| **Payments**       | Stripe API (v20.0.0)                |
| **Security**       | Bcrypt (v6.0.0), CORS, Dotenv       |

---

## 🔑 Environment Variables

To run this server locally, create a `.env` file in the root directory and add the following credentials:

```env
# Server Configuration
PORT=5000

# Database Connection
DB_USER=your_mongodb_username
DB_PASS=your_mongodb_password

# Security (JWT)
ACCESS_TOKEN_SECRET=your_complex_random_secret_string

# Payment Gateway
STRIPE_SECRET_KEY=your_stripe_secret_key
```

## 🛣️ API Structure

The API is organized into efficient endpoints handling specific resources:

- **`/jwt`** - Handles token generation and cookie setting/clearing.
- **`/users`** - User management and role updates (Admin only).
- **`/scholarships`** - CRUD operations for scholarship listings.
- **`/apply`** - Management of student applications.
- **`/create-payment-intent`** - Stripe integration for processing fees.
- **`/reviews`** - Handling user feedback and ratings.
- **`/admin-stats`** - Aggregated data for the admin dashboard.

---

## 🧪 Deployment Checklist

- ✅ **Live Server:** Deployed on Vercel/Render.
- ✅ **Database:** Hosted on MongoDB Atlas.
- ✅ **Security:** SSL enabled and Environment Variables configured in production.

---

<div align="center">
  <p>Made with ❤️ by Muhammad Mahfuj</p>
</div>
