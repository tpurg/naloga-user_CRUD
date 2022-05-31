import {NextFunction, Request, Response} from "express";
import jwt from "jsonwebtoken";
import {accessTokenSecret} from "./usersService";

export const authenticateJWT = (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1];

        jwt.verify(token, accessTokenSecret, (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
            
            next();
        });
    } else {
        res.sendStatus(401);
    }
};
