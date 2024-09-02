import mongoose from "mongoose";
import passportLocalMongoose from "passport-local-mongoose";

let userSchema = new mongoose.Schema({
    userName: String,
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        select: false,
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date
});
userSchema.plugin(passportLocalMongoose, { usernameField: 'email' });
export default mongoose.model('User', userSchema, 'user');