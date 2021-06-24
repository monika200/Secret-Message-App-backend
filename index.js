const express = require('express');
const JWT = require("jsonwebtoken")
const mongodb = require('mongodb');
const bcryptjs = require('bcryptjs');
const nodemailer = require('nodemailer');
const cors = require('cors');
const dotenv = require('dotenv');


const app = express();
app.use(express.json());
app.use(cors());
dotenv.config();

const PORT = process.env.PORT || 3000;
const mongoClient = mongodb.MongoClient;
const DB_URL = process.env.DB_URL 
	
const EMAIL = process.env.EMAIL;
const PASSWORD = process.env.PASSWORD;

	
const transporter = nodemailer.createTransport(({
	service:"gmail",
	 auth: {
		 user: EMAIL,
		 pass: PASSWORD
	 }
	 
 }));

const mailData = {
	from: EMAIL,
	subject: 'SECRET MESSAGE FOR YOU',
};

const mailMessage = (url) => {
	console.log(url);
	return `<p>Hello, <br />
      You have a SECRET MESSAGE waiting for only you to open. <br />
      <a href='${url}' target="_blank">click here to see SECRET message</a> <br/>   
      </p>`;
};

const tokenValidation = (req, res, next) => {
	if(req.headers.authorization !=undefined){
	JWT.verify(req.headers.authorization, process.env.JWT_SECRET_KEY, (error, decodeData) => {
if (decodeData){
	console.log(decodeData)
	req.body.key = decodeData.secretKey;
	next()
}else{
	res.send('invalid token')
}
	})
	}else{
		res.status(401).json({message: 'no token'});
	}
}

app.get('/', (req, res) => {
	res.send('Welcome to secret messaging service app');
});

app.post('/create-message', async (req, res) => {
	try {
		const client = await mongoClient.connect(DB_URL);
		const db = client.db('secrets');
		const salt = await bcryptjs.genSalt(10);
		const hash = await bcryptjs.hash(req.body.password, salt);
		req.body.password = hash;
		const data = {
			key: req.body.randomKey,
			password: req.body.password,
			message: req.body.message
		}
		await db.collection('secrets').insertOne(data);
		const result = await db.collection('secrets').findOne({ key: data.key });
		console.log(result);
		//console.log(mailData, transporter);
		const usrMailUrl = `${req.body.targetUrl}?rs=${result._id}`;
		mailData.to = req.body.targetMail;
		mailData.html = mailMessage(usrMailUrl);
		await transporter.sendMail(mailData)
		//console.log(result.message);
        res.status(200).json({
			message: "secret message is send. Don't forget yout secret key and password",
			result,
		});
		client.close();
	} catch (error) {
		console.log(error);
		res.json({ message: 'Something wend wrong' });
	}
});

app.get('/message-by-id/:id', async (req, res) => {
	try {
		const client = await mongoClient.connect(DB_URL);
		const db = client.db('secrets');
		const result = await db.collection('secrets').findOne({ _id: mongodb.ObjectID(req.params.id) });
		if (!result) {
			res.json({ message: 'null' });
		} else {
			res.json({ message: 'Message has been fetched successfully', result: result.message });
		}
		client.close();
	} catch (error) {
		console.log(error);
		res.json({ message: 'Something wend wrong' });
	}
});

app.delete('/delete-message', async (req, res) => {
	try {
		const client = await mongoClient.connect(DB_URL);
		const db = client.db('secrets');
		const secret = await db.collection('secrets').findOne({ key: req.body.secretKey });
		if (secret) {
			const compare = await bcryptjs.compare(req.body.password, secret.password);
			if (compare) {
				await db.collection('secrets').findOneAndDelete({ key: req.body.secretKey });
				const token = JWT.sign({
					data: req.body.secretKey
				},process.env.JWT_SECRET_KEY, {expireIn: '1h'});
				console.log(token)
				if(token){
					res.status(200).json({ message: 'Message has been deleted SuccessfullY',token });
				}
			} else {
				res.status(401).json({ message: 'Incorrect Password' });
			}
		} else {
			res.status(404).json({ message: 'Secret key not found' });
		}
		client.close();
	} catch (error) {
		console.log(error);
		res.sendStatus(500).json({ message: 'Something wend wrong' });
	}
});


app.post('/validate-token', [tokenValidation], async (req, res) => {
	try{
		const key = req.body.key
		// console.log(key)
res.status(200).json({message: "token validation successfull", key})
	}catch (error) {
	console.log(error);
	res.sendStatus(500);
	}
})
app.listen(PORT, () => console.log(`server started on port : ${PORT}`));
