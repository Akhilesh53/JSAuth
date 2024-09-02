import express from 'express';
import passport from 'passport';
import userSchema from '../models/userschema.js';
import async from 'async';
import nodemailer from 'nodemailer';
import crypto from 'crypto';

const userRouter = express.Router();

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    console.log('User not authenticated. Pls login first to access this page');
    res.redirect('/login');
}


//get requests
userRouter.get('/dashboard', isAuthenticated, (req, res) => {
    res.render('dashboard');
});

userRouter.get('/login', (req, res) => {
    res.render('login', { currentUser: null });
});

userRouter.post('/login', passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: 'Invalid email or password. Try Again!!!'
}));

userRouter.get('/logout', isAuthenticated, (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error(err);
            return;
        }
    });
    console.log('User logged out');
    res.redirect('/login');
})

userRouter.get('/signup', (req, res) => {
    res.render('signup', { currentUser: null });
})

//post requests
userRouter.post('/signup', (req, res) => {
    let { name, email, password } = req.body;

    let userData = {
        name: name,
        email: email
    };

    userSchema.register(userData, password, (err, user) => {
        if (err) {
            req.flash('error_msg', 'ERROR: ' + err);
            res.redirect('/signup');
        }
        passport.authenticate('local')(req, res, () => {
            req.flash('success_msg', 'Account created successfully');
            res.redirect('/login');
        });
    });

});

// forgot password
userRouter.get('/forgot', (req, res) => {
    res.render('forgot', { currentUser: null });
});

userRouter.post('/forgot', (req, res) => {
    async.waterfall([
        // generate token
        (done) => {
            crypto.randomBytes(20, (err, buf) => {
                let token = buf.toString('hex');
                done(err, token);
            });
        },
        // find user
        (token, done) => {
            userSchema.findOne({ email: req.body.email })
                .then((user) => {
                    if (!user) {
                        req.flash('error_msg', 'No account with that email address exists');
                        return res.redirect('/forgot');
                    }
                    user.resetPasswordToken = token;
                    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

                    user.save().then(() => {
                        done(null, token, user);
                    }).catch((err) => {
                        done(err, null, null);
                    })
                }).catch((err) => {
                    req.flash('error_msg', 'Error: ' + err)
                    res.redirect('/forgot');
                })
        },

        (token, user) => {
            let smtpTransport = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: process.env.GMAIL_EMAIL,
                    pass: process.env.GMAIL_PASSWORD
                },
                secure: false,
                port: 587
            })

            let mailOptions = {
                to: user.email,
                from: 'Akhilesh Mahajan <akhileshmahajan3107@gmail.com>',
                subject: 'Node.js Password Reset',
                text: 'You are receiving this because you (or someone else) have requested the reset of the password.\n\n' +
                    'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
                    'http://' + req.headers.host + '/reset/' + token + '\n\n' +
                    'If you didnot request, pls ignore this email and your password will remain unchanged.\n'
            }

            smtpTransport.sendMail(mailOptions, (err) => {
                req.flash('success_msg', 'An email has been sent to ' + user.email + ' with further instructions');
                res.redirect('/login');
            })
        }
    ], (err) => {
        if (err) {
            req.flash('error_msg', 'Error: ' + err);
            res.redirect('/forgot');
        }
        res.redirect('/forgot');
    })
})

userRouter.get('/password/change', isAuthenticated, (req, res) => {
    res.render('changepassword');
})

userRouter.post('/password/change', isAuthenticated, (req, res) => {
    let newPassword = req.body.password;

    userSchema.findOne({ email: req.user.email })
        .then((user) => {
            user.setPassword(newPassword, (err, user) => {
                if (err) {
                    req.flash('error_msg', 'Error: ' + err);
                    res.redirect('/password/change');
                }
                user.save();
                req.flash('success_msg', 'Password changed successfully');
                res.redirect('/login');
            });
        }).catch(err => {
            req.flash('error_msg', 'Error: ' + err);
            res.redirect('/password/change');
        });

})


userRouter.get('/reset/:token', (req, res) => {
    // find user from token
    userSchema.find({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } })
        .then((user) => {
            if (!user) {
                req.flash('error_msg', 'Password reset token is invalid or has expired');
                return res.redirect('/forgot');
            }

            res.render('newpassword', { token: req.params.token });
        }).catch((err) => {
            req.flash('error_msg', 'Error: ' + err);
            res.redirect('/forgot');
        })
})

userRouter.post('/reset/:token', (req, res) => {
    async.waterfall([
        // Find the user using the token
        (done) => {
            userSchema.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gte: Date.now() } })
                .then((user) => {
                    if (!user) {
                        req.flash('error_msg', 'Password reset token is invalid or has expired');
                        return res.redirect('/forgot');
                    }

                    // Check if new password and confirm password match
                    if (req.body.password !== req.body.confirmpassword) {
                        req.flash('error_msg', 'Passwords do not match');
                        return res.redirect('/forgot');
                    }

                    // Update the password
                    user.setPassword(req.body.password, (err) => {
                        if (err) {
                            req.flash('error_msg', 'Error in updating password');
                            return res.redirect('/forgot');
                        }
                        user.resetPasswordToken = undefined;
                        user.resetPasswordExpires = undefined;

                        user.save().then(() => {
                            req.logIn(user, (err) => {
                                if (err) return done(err);
                                done(null, user);
                            });
                        }).catch((err) => {
                            done(err);
                        });
                    });
                })
                .catch((err) => {
                    done(err);
                });
        },

        // Send confirmation email
        (user, done) => {
            let smtpTransport = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: process.env.GMAIL_EMAIL,
                    pass: process.env.GMAIL_PASSWORD
                },
                secure: false,
                port: 587
            });

            let mailOptions = {
                to: user.email,
                from: 'Akhilesh Mahajan <akhileshmajan3107@gmail.com>',
                subject: 'Your password has been changed',
                text: `Hello,\n\nThis is a confirmation that the password for your account ${user.email} has been changed.\n`
            };

            smtpTransport.sendMail(mailOptions, (err) => {
                req.flash('success_msg', 'Success! Your password has been changed.');
                done(null);
            });
        }
    ], (err) => {
        if (err) {
            req.flash('error_msg', 'Error: ' + err.message);
            return res.redirect('/forgot');
        }
        res.redirect('/login');
    });
});


export default userRouter;