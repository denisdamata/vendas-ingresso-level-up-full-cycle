import express from 'express';
import * as mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';
import jwt from "jsonwebtoken";

function createConnection(){
    return mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'root',
        database: 'tickets',
        port: 33061
    })
}

// O `express` é bom para MVC, Model View Controller (arquitetura de camadas), e também para Middleware, que são vários Controller antes do Controller principal (arquitetura Onion Style). 
const app = express();

app.use(express.json());

const unprotectedRoutes = [
    { method: "POST", path: "/auth/login" },
    { method: "POST", path: "/customers/register" },
    { method: "POST", path: "/partners/register" },
    { method: "GET", path: "/events" },
  ];

app.use(async (req, res, next) => {
    console.log('Received request:', req.method, req.path);
    console.log('Headers:', req.headers);

    const isUnprotectedRoute = unprotectedRoutes.some(
        (route) => route.method == req.method && req.path.startsWith(route.path)
    );
    
    if (isUnprotectedRoute){
        return next();
    }

    const token = req.headers['authorization']?.split(" ")[1];
    console.log('APP USE token', token);
    if (!token){
        res.status(401).json({message: "No token provided!"});
        return;
    }
    try {
        const payload = jwt.verify(token, '123456') as {id: number; email: string};
        const connection = await createConnection();
        const [rows] = await connection.execute<mysql.RowDataPacket[]>(
            'SELECT * FROM users WHERE id = ?', [payload.id]
        );
        const user = rows.length ? rows[0]: null;
        if (!user){
            res.status(401).json({message: "Failed to authenticate token!"});
            return;
        }
        req.user = user as {id: number; email: string};
        next();
    } catch (error) {
        res.status(401).json({message: "Failed to authenticate token!"});
    }
});

app.get('/', (req, res) => {
    res.json({message: "Hello World!"});
});

app.post('/auth/login', async (req, res) => {
    console.log('POST /auth/login');
    const {email, password} = req.body;
    console.log(email, password);
    const connection = await createConnection();
    try {
        const [rows] = await connection.execute<mysql.RowDataPacket[]>(
            'SELECT * FROM users WHERE email = ?', [email]
        );
        const user = rows.length ? rows[0]: null;
        if (user && bcrypt.compareSync(password, user.password)){
            const token = jwt.sign({id: user.id, email: user.email}, "123456", {expiresIn: "1h"});
            res.json({token});
        }else{
            res.status(401).json({message: "Invalid credentials"});
        }
    }catch(error){
        console.log(error);
    }finally{
        await connection.end();
    }
    res.send();
});

app.post('/partners/register', async (req, res) => {
    console.log('POST /partners/register');
    const { name, email, password, company_name } = req.body;

    const connection = await createConnection(); 

    try {
        const createdAt = new Date();
        const hashedPassword = bcrypt.hashSync(password, 10);

        const [userResult] = await connection.execute<mysql.ResultSetHeader>(
            'INSERT INTO users (name, email, password, created_at) VALUES (?, ?, ?, ?)', 
            [
                name,
                email,
                hashedPassword,
                createdAt
            ]
        );

        const userId = userResult.insertId;

        const [partnerResult] = await connection.execute<mysql.ResultSetHeader>(
            'INSERT INTO partners (user_id, company_name, created_at) VALUES (?, ?, ?)', 
            [
                userId,
                company_name,
                createdAt
            ]
        ); 

        res.status(201).json({
            id: partnerResult.insertId,
            name,
            user_id: userId,
            company_name,
            created_at: createdAt
        });
    }catch(error){
        console.log(error);
    } finally {
        await connection.end();
    } 
});

// Esta função abaixo é para o `customers`, ao invés de `partners`, e é quase igual a função anterior, apenas muda alguns parâmetros. Fica como exercício abstrair essa duas funções em um só.
app.post('/customers/register', async (req, res) => {
    const {name, email, password, address, phone} = req.body;

    const connection = await createConnection(); 

    try {
        const createdAt = new Date();
        const hashedPassword = bcrypt.hashSync(password, 10);

        const [userResult] = await connection.execute<mysql.ResultSetHeader>(
            'INSERT INTO users (name, email, password, created_at) VALUES (?, ?, ?, ?)', 
            [
                name,
                email,
                hashedPassword,
                createdAt
            ]
        );

        const userId = userResult.insertId;

        const [customersResult] = await connection.execute<mysql.ResultSetHeader>(
            'INSERT INTO customers (user_id, address, phone, created_at) VALUES (?, ?, ?, ?)', 
            [
                userId,
                address,
                phone,
                createdAt
            ]
        );

        res.status(201).json({
            id: customersResult.insertId,
            name,
            user_id: userId,
            address,
            phone,
            created_at: createdAt
        });
    } finally {
        await connection.end();
    }
});

app.post('/partners/events', async (req, res) => {
    console.log('POST /partners/events');
    console.log('Request body:', req.body);
    const {name, description, date, location} = req.body;
    const userId = req.user!.id;
    const connection = await createConnection();
    try{
        const [rows] = await connection.execute<mysql.RowDataPacket[]>(
            'SELECT * FROM partners WHERE user_id = ?', [userId]
        );
        const partner = rows.length ? rows[0] : null;

        if (!partner){
            res.status(403).json({message: "Not authorized!"});
            return;
        }
        const eventDate = new Date(date);
        const createdAt = new Date();
        const [eventResult] = await connection.execute<mysql.ResultSetHeader>(
            'INSERT INTO events (name, description, date, location, created_at, partner_id) VALUES (?, ?, ?, ?, ?, ?)', 
            [
                name,
                description,
                eventDate,
                location, 
                createdAt,
                partner.id
            ]
        );
        res.status(201).json({
            id: eventResult.insertId, 
            name, 
            description, 
            date: eventDate, 
            location, 
            created_at: createdAt, 
            partner_id: partner.id
        });
    }catch(error){
        console.log(error);
    }finally{
        await connection.end();
    }
});  

app.get('/partners/events', async (req, res) => {
    console.log('GET /partners/events');
    const userId = req.user!.id;
    const connection = await createConnection();
    try{
        const [rows] = await connection.execute<mysql.RowDataPacket[]>(
            'SELECT * FROM partners WHERE user_id = ?', [userId]
        );
        const partner = rows.length ? rows[0] : null;
        
        if (!partner){
            res.status(403).json({message: "Not authorized!"});
            return;
        }
        const [eventRows] = await connection.execute<mysql.RowDataPacket[]>(
           'SELECT * FROM events WHERE partner_id = ?', [partner.id]
        );
        res.json(eventRows);
    }catch(error){
        console.log(error);
    }finally{
        await connection.end();
    } 
});

app.get('/partners/events/:eventId', async (req, res) => {
    const {eventId} = req.params;
    const userId = req.user!.id;
    const connection = await createConnection();
    try{
        const [rows] = await connection.execute<mysql.RowDataPacket[]>(
            'SELECT * FROM partners WHERE user_id = ?', [userId]
        );
        const partner = rows.length ? rows[0] : null;
        
        if (!partner){
            res.status(403).json({message: "Not authorized!"});
            return;
        }
        const [eventRows] = await connection.execute<mysql.RowDataPacket[]>(
           'SELECT * FROM events WHERE partner_id = ? AND id = ?', [partner.id, eventId]
        );
        const event = eventRows.length ? rows[0] : null;
        if (!event){
            res.status(404).json({messge: "Event not found!"});
        }
        res.json(event);
    }catch(error){
        console.log(error);
    }finally{
        await connection.end();
    } 
});

app.get('/events', async (req, res) => {
    const connection = await createConnection();
    try{
        const [eventRows] = await connection.execute<mysql.RowDataPacket[]>(
           'SELECT * FROM events'
        );
        res.json(eventRows);
    }catch(error){
        console.log(error);
    }finally{
        await connection.end();
    } 
});

app.get('/events/:eventId', async (req, res) => {
    const {eventId} = req.params;
    const connection = await createConnection();
    try{
        const [eventRows] = await connection.execute<mysql.RowDataPacket[]>(
           'SELECT * FROM events WHERE id = ?', [eventId]
        );

        const event = eventRows.length ? eventRows[0] : null;
        if (!event){
            res.status(404).json({messge: "Event not found!"});
        }
        res.json(eventRows);
    }catch(error){
        console.log(error);
    }finally{
        await connection.end();
    } 
});

app.listen(3000, async () => {
    try {                                                                       // Se você quiser lidar com erros que possam ocorrer em uma função assíncrona, é uma boa prática usar um bloco `try...catch` [ChatGPT].
        await cleanLastSession();
        console.log('Running in http://localhost:3000');
    } catch (error) { 
        console.error('Error cleaning last session:', error);
    }
});

async function cleanLastSession(){                                             // Só de editar e salvar este arquivo a sessão anterior é limpa.
    const connection = await createConnection();
    await connection.execute("SET FOREIGN_KEY_CHECKS = 0");
    const tables = ["events", "customers", "partners", "users"];
    for (const table of tables) { 
        await connection.execute(`TRUNCATE TABLE ${table}`);
    }
    await connection.execute("SET FOREIGN_KEY_CHECKS = 1");
};