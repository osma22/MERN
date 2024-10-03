const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth2').Strategy;
const User = require('./models/user'); // Adjust the path as necessary

// Google OAuth Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_OAUTH_REDIRECT_URL,
    passReqToCallback: true
}, async (request, accessToken, refreshToken, profile, done) => {
    try {
        // Check if the user already exists in the database
        let user = await User.findOne({ googleId: profile.id });

        if (!user) {
            // Create a new user if not found
            user = new User({
                googleId: profile.id,
                email: profile.email,
                displayName: profile.displayName,
                token: accessToken,
                refreshToken: refreshToken
            });
            await user.save(); // Save the new user to the database
        } else {
            // Update the existing user's tokens
            user.token = accessToken;
            user.refreshToken = refreshToken;
            await user.save();
        }
        
        return done(null, user); // User authenticated successfully
    } catch (err) {
        return done(err, false); // Authentication failed
    }
}));

// Serialize user into the session
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Deserialize user from the session
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id); // Find user by ID
        done(null, user); // Return the user object
    } catch (err) {
        done(err, null); // Return error if user not found
    }
});
