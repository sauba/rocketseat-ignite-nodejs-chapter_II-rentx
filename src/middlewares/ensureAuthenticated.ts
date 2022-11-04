import { NextFunction, Request, Response } from "express";
import { verify } from "jsonwebtoken";
import { AppError } from "../errors/AppError";
import { UsersRepository } from "../modules/accounts/repositories/implementations/UsersRepository";

interface IPayload {
  sub: string;
}

export async function ensureAuthenticated(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    throw new AppError("Token is Missing", 401);
  }

  const [, token] = authHeader.split(" ");

  try {
    const { sub: user_id } = verify(
      token,
      "d6380aa505446839b910cb6a1dc66ca9"
    ) as IPayload;

    const usersRepository = new UsersRepository();
    const user = await usersRepository.findById(user_id);

    if (!user) {
      throw new AppError("User does not exists.", 401);
    }

    req.user = {
      id: user_id,
    };

    next();
  } catch (error) {
    throw new AppError("Invalid Token", 401);
  }
}
