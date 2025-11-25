
var exec = require('cordova/exec');

exports.isSecure = function(successCallback, errorCallback) {
    exec(successCallback, errorCallback, "SecurityPlugin", "isSecure", []);
};
