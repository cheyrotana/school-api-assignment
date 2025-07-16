import express from "express";
import {
  register,
  logIn,
  getAllUsers,
} from "../controllers/login.controller.js";
import verifyToken from "../middleware/jwtMiddleware.js";

const route = express.Router();

route.post("/register", register);
route.post("/login", logIn);
route.get("/users", verifyToken, getAllUsers);

export default route;
