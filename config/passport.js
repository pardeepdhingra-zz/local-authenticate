//load all the things we need

var LocalStrategy = require('passport-local').Strategy;

//load the user model
var User  = require('../app/models/user');

//expose this function to out app using module.exports

module.exports = function(passport) {

	//passport session setup
	//passport needs ability to serialize and unserialize users out of session
	
	passport.serializeUser(function(user, done) {
		done(null, user.id);
	});


	passport.deserializeUser(function(id, done) {
		User.findById(id, function(err, user){
			done(err, user);
		});
	});
	
	//===============================================================
	//LOCAL-SIGNUP
	//we are using named strategies since we have one for login and one for signup
	//by default local strategy uses username and password, we will override with email
	//===============================================================


	passport.use('local-signup', new LocalStrategy({
		usernameField 	: "email",
		passwordField	: "password", 
		passReqToCallback	: true //allow us to pass back the entire request to the callback
	},
	function(req, email, password, done){
		//asyncronous
		//User.findOne wont fire unless data is sent back
		process.nextTick(function(){

			//find a user whose email is the same as the forms email
			//we are checking to see if the user already exists

			User.findOne({'local.email' : email }, function(err, user){
				if(err)
					return done(err);

				//check to see if theres already a user with that email

				if (user) {
					return done(null, false, req.flash('signupMessage', 'That email is already taken'));
				} else {

					//if there is no user with that email
					//create the user

					var newUser = new User();
					newUser.local.email = email;
					newUser.local.password = newUser.generateHash(password);

					//save the user details
					console.log(newUser);

					newUser.save(function(err) {
						if(err)
							throw err;

						return done(null, newUser);
					});
				}
			});
		});
	}));



	//===============================================================
	//LOCAL-SIGNUP
	//we are using named strategies since we have one for login and one for signup
	//by default local strategy uses username and password, we will override with email
	//===============================================================


	passport.use('local-signin', new LocalStrategy({
		usernameField 	: "email",
		passwordField	: "password", 
		passReqToCallback	: true //allow us to pass back the entire request to the callback
	},
	function(req, email, password, done){
		//find a user whose email is the same as the forms email
		User.findOne({'local.email' : email }, function(err, user){
			if(err)
				return done(err);

			//check to see if user and password match

			if (!user) {
				return done(null, false, req.flash('loginMessage', 'No User Find'));
			} 

			if (!user.validPassword(password)) 
				return done(null, false, req.flash('loginMessage', 'Oops! wrong email id or password'));

			//all is well, return successful user
			return done(null, user);
		});
	}));

};