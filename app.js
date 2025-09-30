import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { configDotenv } from "dotenv";
import connectDB from "./server.js";
import userRoutes from "./routes/userroutes.js";
configDotenv();

const app = express();

app.use(cookieParser());
//so the backedn will recieve cookie from frontend by doing this in cors
app.use(
  cors({
    origin: ["http://localhost:3000","https://next-app-auth-frontend-bnvl.vercel.app"],
    credentials: true,
  })
);
app.use(express.json());

app.use("/api/users", userRoutes);

const PORT = process.env.PORT;

const startServer = async () => {
  try {
    await connectDB();
    app.listen(PORT, () => {
      console.log("Server has started at port :", PORT);
    });
  } catch (error) {
    console.error("Failed to connect to the database:", error);
    process.exit(1);
  }
};

startServer();

export default app;
