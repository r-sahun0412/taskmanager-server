const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const app = express();

app.use(express.static(path.join(__dirname + '/public')));
const PORT = process.env.PORT || 2700;

const constr = 'mongodb://127.0.0.1:27017';

app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const JWT_SECRET = 'JWTKEY';

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Login User
app.post('/login', async (req, res) => {
    const { UserId, Password } = req.body;

    let client;
    try {
        client = await MongoClient.connect(constr);
        const db = client.db('task');
        const user = await db.collection('users').findOne({ UserId });

        if (!user) return res.status(400).send('User not found');
        if (await bcrypt.compare(Password, user.Password)) {
            const token = jwt.sign({ UserId: user.UserId }, JWT_SECRET, { expiresIn: '1h' });
            return res.json({ token });
        } else {
            return res.status(401).send('Invalid password');
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    } finally {
        if (client) client.close();
    }
});

// Register User
app.post('/registeruser', async (req, res) => {
    const user = {
        UserId: req.body.UserId,
        UserName: req.body.UserName,
        Password: req.body.Password,
        Email: req.body.Email,
        Mobile: req.body.Mobile
    };

    let client;
    try {
        client = await MongoClient.connect(constr);
        const db = client.db('task');
        const existingUser = await db.collection('users').findOne({
            $or: [
                { UserId: user.UserId },
                { Email: user.Email },
                { Mobile: user.Mobile }
            ]
        });

        if (existingUser) {
            res.status(400).send('User already exists');
        } else {
            const salt = await bcrypt.genSalt(10);
            user.Password = await bcrypt.hash(user.Password, salt);
            await db.collection('users').insertOne(user);
            res.status(201).send('User registered successfully');
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    } finally {
        if (client) client.close();
    }
});

// Get All Tasks (Protected Route)
app.get("/task", authenticateToken, async (req, res) => {
    const userId = req.user.UserId; // Get user ID from the token

    let client;
    try {
        client = await MongoClient.connect(constr);
        const db = client.db("task");
        const tasks = await db.collection("task").find({ UserId: userId }).toArray(); // Filter tasks by user ID
        res.send(tasks);
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    } finally {
        if (client) client.close();
    }
});


// Fetch a specific task by ID (Protected Route)
app.get("/task/:id", authenticateToken, async (req, res) => {
    const taskId = req.params.id;

    let client;
    try {
        client = await MongoClient.connect(constr);
        const db = client.db("task");
        const task = await db.collection("task").findOne({ _id: new ObjectId(taskId) });

        if (!task) {
            return res.status(404).send('Task not found');
        }

        res.send(task);
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    } finally {
        if (client) client.close();
    }
});


// Get Tasks by Status (Protected Route)
app.get("/task/:status", authenticateToken, async (req, res) => {
    const status = req.params.status;
    const query = status === "completed" ? { completed: true } : status === "pending" ? { completed: false } : {};

    let client;
    try {
        client = await MongoClient.connect(constr);
        const db = client.db("task");
        const tasks = await db.collection("task").find(query).toArray();
        res.send(tasks);
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    } finally {
        if (client) client.close();
    }
});

// Add Task
// Add Task
app.post("/addtask", authenticateToken, async (req, res) => {
    const task = {
        UserId: req.user.UserId, // Add user ID to the task
        TaskName: req.body.TaskName,
        TaskDescription: req.body.TaskDescription
    };

    let client;
    try {
        client = await MongoClient.connect(constr);
        const db = client.db("task");
        await db.collection("task").insertOne(task);
        res.status(201).send('Task added successfully');
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    } finally {
        if (client) client.close();
    }
});

// Update Task
app.put("/updatetask/:id", authenticateToken, async (req, res) => {
    const taskIdToUpdate = req.params.id;
    const updatedTask = {
        TaskName: req.body.TaskName,
        TaskDescription: req.body.TaskDescription
    };

    let client;
    try {
        client = await MongoClient.connect(constr);
        const db = client.db("task");
        await db.collection("task").updateOne(
            { _id: new ObjectId(taskIdToUpdate) },
            { $set: updatedTask }
        );
        res.send('Task updated successfully');
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    } finally {
        if (client) client.close();
    }
});

// Delete Task
app.delete("/deletetask/:id", authenticateToken, async (req, res) => {
    const taskIdToDelete = req.params.id;

    let client;
    try {
        client = await MongoClient.connect(constr);
        const db = client.db("task");
        const result = await db.collection("task").deleteOne({ _id: new ObjectId(taskIdToDelete) });

        if (result.deletedCount === 1) {
            res.send("Task deleted successfully");
        } else {
            res.status(404).send("Task not found");
        }
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    } finally {
        if (client) client.close();
    }
});

// Mark task as completed
app.put("/markcompleted/:id", authenticateToken, async (req, res) => {
    const taskIdToUpdate = req.params.id;

    let client;
    try {
        client = await MongoClient.connect(constr);
        const db = client.db("task");
        await db.collection("task").updateOne(
            { _id: new ObjectId(taskIdToUpdate) },
            { $set: { completed: true } }
        );
        res.send("Task marked as completed");
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    } finally {
        if (client) client.close();
    }
});

// Mark task as incomplete
app.put("/markincomplete/:id", authenticateToken, async (req, res) => {
    const taskIdToUpdate = req.params.id;

    let client;
    try {
        client = await MongoClient.connect(constr);
        const db = client.db("task");
        await db.collection("task").updateOne(
            { _id: new ObjectId(taskIdToUpdate) },
            { $set: { completed: false } }
        );
        res.send("Task marked as incomplete");
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    } finally {
        if (client) client.close();
    }
});

// Get Users
app.get("/users", authenticateToken, async (req, res) => {
    let client;
    try {
        client = await MongoClient.connect(constr);
        const db = client.db("task");
        const users = await db.collection("users").find({}).toArray();
        res.send(users);
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    } finally {
        if (client) client.close();
    }
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server Started: http://localhost:${PORT}`);
});
