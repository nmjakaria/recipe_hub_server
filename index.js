const dns = require("node:dns");
// 1. Fix DNS lookup issues globally in your Node app
dns.setServers(["8.8.8.8", "8.8.4.4"]);

const express = require("express");
const dotenv = require('dotenv');
const cors = require('cors');
const { MongoClient, ObjectId, ServerApiVersion } = require('mongodb');

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.SERVER_PORT || 5000;
const uri = process.env.MONGO_DB_URI;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// 2. Connect to MongoDB ONCE when the server starts
async function startServer() {
    try {
        await client.connect();

        const database = client.db("recipeHub_db");
        
        

        await client.db("admin").command({ ping: 1 });
        console.log("Connected to MongoDB successfully!");

        // Start listening only AFTER database connection succeeds
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });

    } catch (error) {
        console.error("Failed to connect to the database:", error);
        process.exit(1); // Exit process if DB connection fails
    }
}

// Global routes
app.get('/', (req, res) => {
    res.send('HrieLoop Server is running!');
});

startServer();