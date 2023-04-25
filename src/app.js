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
    password: joi.string().required().min(3)
  });


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
        res.status(201).send("Cadastrado com sucesso!!");
    } catch (err) {
        res.status(500).send(err.message)
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
            const token = uuid();
            await db.collection("sessions").insertOne({userId: user._id,token})
            return res.status(200).send(token)
        } else {
            res.status(401).send("Senha errada!")
        }
    } catch (err) {
        res.status(500).send(err.message)
    }
})

server.listen(5000, () => console.log("Servidor aberto na porta 5000"))