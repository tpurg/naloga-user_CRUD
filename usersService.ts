import express, {Request, Response} from 'express';
import {Users} from "./Users";
import {User} from "./User";
import {userJoi} from "./userJoi"
import jwt from "jsonwebtoken";
import {authenticateJWT} from "./auth.middleware";

export const accessTokenSecret = 'tokenSecret';
const refreshTokenSecret = 'refreshTokenSecret';
let refreshTokens: String[] = [];

export const usersService = (app: express.Application) => {
    app.get('/users', authenticateJWT, (req: Request, res: Response) => {
        res.status(200).send(Users);
    });

    app.get('/users/:uid', authenticateJWT, (req: Request, res: Response) => {
        const user: User | undefined = Users.find(user => {
            return user.id.toString(10) === req.params.uid
        })

        if (user === undefined) {
            res.status(404).send("User doesn't exist")
        } else {
            res.status(200).send(user);
        }
    });

    app.post('/users', authenticateJWT, (req: Request, res: Response) => {
        const user: User = req.body;

        const result = userJoi.validate(user);

        if (result.error !== undefined) {
            res.status(400).send("Bad request: " + result.error)
        } else {
            const userExists = Users.find( u => {return u.userName === user.userName})

            if (userExists === undefined) {
                Users.push(new User(Users.length+1, user.userName, user.password))
                res.status(201).send(req.body);
            } else {
                res.status(400).send("Username already taken");
            }
        }
    });

    app.post('/login', (req: Request, res: Response) => {
        const userBody: User = req.body;

        const user = Users.find(u => {return u.userName === userBody.userName && u.password === userBody.password});

        if (user) {
            const accessToken = jwt.sign({username: user.userName}, accessTokenSecret, {expiresIn: '20m'});
            const refreshToken = jwt.sign({username: user.userName}, refreshTokenSecret, {expiresIn: '40m'});

            refreshTokens.push(refreshToken);

            res.json({
                accessToken,
                refreshToken
            });
        } else {
            res.status(400).send('Username or password incorrect');
        }
    });

    app.put('/users/:uid', authenticateJWT, (req: Request, res: Response) => {
        const user: User = req.body;

        const result = userJoi.validate(user);

        if (result.error !== undefined) {
            res.status(400).send("Bad request: " + result.error)
        } else {
            let userExists = Users.find(u => {return u.id.toString() === req.params.uid});

            if (userExists === undefined) {
                res.status(404).send("User doesn't exist");
            } else {
                userExists = Users.find(u => {return u.userName === user.userName});

                if (userExists === undefined) {
                    const userIndex = Users.findIndex(u => {return u.id.toString() === req.params.uid})

                    Users[userIndex].userName = user.userName
                    Users[userIndex].password = user.password

                    res.status(200).json(req.body);
                } else {
                    res.status(400).send("Username already taken");
                }
            }
        }
    });

    app.delete('/users/:uid', authenticateJWT, (req: Request, res: Response) => {
        const user = Users.findIndex(u => {
            return u.id.toString() === req.params.uid
        });

        if (user === undefined) {
            res.status(404).send(JSON.parse("User doesn't exist"));
        } else {
            Users.splice(user, 1)

            res.status(200).send(`User ${req.params.uid} was deleted`);
        }
    });

    app.post('/token', (req: Request, res: Response) => {
        const {token} = req.body;

        if (token === undefined) {
            res.status(401).send("Unathorized");
            return
        }

        if (!refreshTokens.includes(token)) {
            res.status(401).send("Unathorized");
            return;
        }

        jwt.verify(token, refreshTokenSecret, {complete: true}, (err, user) => {
            if (err) {
                res.status(403).send("Bad request");
                return
            }

            if (user !== undefined) {

                const accessToken = jwt.sign({username: user}, accessTokenSecret, {expiresIn: '20m'});

                res.json({
                    accessToken
                });
            }
        });
    });

    app.post('/logout', (req: Request, res: Response) => {
        const {t} = req.body;
        refreshTokens = refreshTokens.filter(token => t !== token);

        res.send("Logout successful");
    });
}


