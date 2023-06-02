const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

const app = express();

app.use(bodyParser.json());
app.use(passport.initialize());

mongoose.connect('mongodb://localhost:27017', { useNewUrlParser: true, useUnifiedTopology: true });

const customerSchema = new mongoose.Schema({
  username: String,
  password: String,
  cart: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }]
});

customerSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

const productSchema = new mongoose.Schema({
  name: String,
  price: Number,
  customers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Customer' }]
});

const Customer = mongoose.model('Customer', customerSchema);
const Product = mongoose.model('Product', productSchema);

const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: 'secret'
};

passport.use(new JwtStrategy(opts, async (jwt_payload, done) => {
  const customer = await Customer.findById(jwt_payload.id);
  if (customer) {
    return done(null, customer);
  } else {
    return done(null, false);
  }
}));
// CRUD для покупця
app.post('/customer', async (req, res) => {
  const customer = new Customer(req.body);
  await customer.save();
  res.send(customer);
});

app.get('/customer/:id', passport.authenticate('jwt', { session: false }), async (req, res) => {
  const customer = await Customer.findById(req.params.id).populate('cart');
  res.send(customer);
});

app.put('/customer/:id', passport.authenticate('jwt', { session: false }), async (req, res) => {
  if (req.body.password) {
    req.body.password = await bcrypt.hash(req.body.password, 10);
  }
  const customer = await Customer.findByIdAndUpdate(req.params.id, req.body, {new: true});
  res.send(customer);
});

app.delete('/customer/:id', passport.authenticate('jwt', { session: false }), async (req, res) => {
  const customer = await Customer.findByIdAndDelete(req.params.id);
  res.send(customer);
});

// Login and register requests
app.post('/register', async (req, res) => {
  const customer = new Customer(req.body);
  await customer.save();
  res.send(customer);
});

app.post('/login', async (req, res) => {
  const customer = await Customer.findOne({ username: req.body.username });
  if (!customer) {
    return res.status(400).send('Invalid username or password.');
  }
  if (!await bcrypt.compare(req.body.password, customer.password)) {
    return res.status(400).send('Invalid username or password.');
  }
  const token = jwt.sign({ id: customer._id }, 'secret');
  res.send({ customer, token });
});



// CRUD для товару
app.get('/product/:id', passport.authenticate('jwt', { session: false }), async (req, res) => {
  const product = await Product.findById(req.params.id).populate('customers');
  res.send(product);
});

app.post('/product', passport.authenticate('jwt', { session: false }), async (req, res) => {
  const product = new Product(req.body);
  await product.save();
  res.send(product);
});

app.put('/product/:id', passport.authenticate('jwt', { session: false }), async (req, res) => {
  const product = await Product.findByIdAndUpdate(req.params.id, req.body, {new: true});
  res.send(product);
});

app.delete('/product/:id', passport.authenticate('jwt', { session: false }), async (req, res) => {
  const product = await Product.findByIdAndDelete(req.params.id);
  res.send(product);
});


app.listen(3000, () => console.log('Listening on port 3000'));
