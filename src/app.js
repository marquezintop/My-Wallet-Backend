import express, { json } from 'express';
import { MongoClient } from 'mongodb';
import cors from 'cors';
import dotenv from 'dotenv';
import joi from 'joi';
import bcrypt from 'bcrypt';
import {v4 as uuid} from 'uuid';

const server = express();

// configs
server.use(cors());
server.use(express.json());
dotenv.config();

// connecting to MongoDB database
const mongoClient = new MongoClient(process.env.DATABASE_URL)
let db

mongoClient.connect().then(() => db = mongoClient.db())

// JOI validations

const signUpSchema = joi.object({
    name: joi.string().required(),
    email: joi.string().email().required(),
    password: joi.string().required().min(3)
});

const signInSchema = joi.object({
    email: joi.string().email().required(),
    password: joi.required()
  });
const transactionsSchema = joi.object({
    value: joi.number().positive().required(),
    description: joi.string().required()
})


server.post("/sign-up", async (req,res) => {
    const { name, email, password } = req.body;

    const validation = signUpSchema.validate(req.body, { abortEarly: false });
    if (validation.error) {
        const errors = validation.error.details.map((detail) => detail.message);
        return res.status(422).send(errors);
    }

    try {
        const checkingUser = await db.collection("users").findOne({email});
        if (checkingUser) return res.status(409).send("E-mail já cadastrado!");
        const encryptedPassword = bcrypt.hashSync(password, 10);
        await db.collection("users").insertOne({name, email, password: encryptedPassword});
        return res.status(201).send("Cadastrado com sucesso!!");
    } catch (err) {
        return res.status(500).send(err.message)
    }
})

server.post("/sign-in", async (req, res) => {
    const { email, password } = req.body;

    const validation = signInSchema.validate(req.body, { abortEarly: false });
    if (validation.error) {
        const errors = validation.error.details.map((detail) => detail.message);
        return res.status(422).send(errors);
    }

    try {
        const user = await db.collection("users").findOne({email});
        if (!user) return res.status(404).send("E-mail não está cadastrado");
        if (bcrypt.compareSync(password, user.password))  {
            const username = user.name
            const token = uuid();
            const session = await db.collection("sessions").insertOne({userId: user._id,token, username})
            return res.status(200).send(session)
        } else {
           return res.status(401).send("Senha errada!")
        }
    } catch (err) {
        return res.status(500).send(err.message)
    }
})

server.post("/transactions", async (req,res) => {
    const { value, description} = req.body;
    const { authorization } = req.headers;

    const token = authorization?.replace('Bearer ', '');
    if(!token) return res.sendStatus(401);

    const validation = transactionsSchema.validate(req.body, { abortEarly: false });
    if (validation.error) {
        const errors = validation.error.details.map((detail) => detail.message);
        return res.status(422).send(errors);
    }

    try {
        const session = await db.collection("sessions").findOne({ token });
        if (!session) return res.sendStatus(401);
        const user = await db.collection("users").findOne({_id: session.userId})
        if (user) {
            await db.collection("transactions").insertOne({value, description, userId: session.userId});
            return res.sendStatus(200);
        } else {
            return res.sendStatus(401);
        }
    } catch (err) {
        return res.status(500).send(err.message);
    }

})

server.get("/transactions", async (req,res) => {
    const { authorization } = req.headers;

    const token = authorization?.replace('Bearer ', '');
    if(!token) return res.sendStatus(401);

    try {
        const session = await db.collection("sessions").findOne({ token });
        if (!session) return res.sendStatus(401);
        console.log(session.userId)
        const transactions = await db.collection("transactions").find({userId: session.userId}).toArray()
        res.status(201).send(transactions);
    } catch (err) {
        return res.status(500).send(err.message)
    }
})

server.listen(5000, () => console.log("Servidor aberto na porta 5000"))