import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import dotenv from "dotenv";
import connectDB from "./utils/db.js";

// Import route files
import userRoute from "./routes/user.route.js";
import authRoute from "./routes/auth.route.js"; // Fixed ES Module export
import companyRoute from "./routes/company.route.js";
import jobRoute from "./routes/job.route.js";
import applicationRoute from "./routes/application.route.js";

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Connect to Database before middleware
connectDB();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS Configuration
const corsOptions = {
//  origin: ["http://localhost:5173"],
    origin: ["https://career-connect-frontend.netlify.app","http://localhost:5173"],
    credentials: true,
};
app.use(cors(corsOptions));

// API Routes
app.use("/api/user", userRoute);
app.use("/api/auth", authRoute); // Registered auth route
app.use("/api/company", companyRoute);
app.use("/api/job", jobRoute);
app.use("/api/application", applicationRoute);

// Handle 404 - Route Not Found
app.use((req, res, next) => {
  res.status(404).json({ message: "Route Not Found" });
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error("Error:", err.message);
  res.status(500).json({ message: "Internal Server Error" });
});

// Start Server
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
