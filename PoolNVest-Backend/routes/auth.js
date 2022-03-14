const Joi = require('joi');
//const bcrypt = require('bcrypt');
const _ = require('lodash');
const {User} = require('../models/user.js');
const mongoose = require('mongoose');
const express = require('express');
const router = express.Router();

  // signup route
  router.post("/signup", async (req, res) => {
    const body = req.body;

    if (!(body.email && body.password)) {
      return res.status(400).send({ error: "Data not formatted properly" });
    }

    const user = new User(body);
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(user.password, salt);
    user.save().then((doc) => res.status(201).send(doc));
  });

router.post('/login', async (req,res) => {
    const { error } = validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    let user = await User.findOne({ username : req.body.username });
    if (!user) return res.status(400).send('Invalid email or password');

    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) return res.status(400).send('Invalid email or password');

    const token = user.generateAuthToken();
    res.send(token);
});

function validate(req) {
    const schema = {
        username : Joi.string().min(5).max(50).required(),
        password: Joi.string().min(5).max(255).required()
    };
    return Joi.validate(req,schema);
}

module.exports = router;