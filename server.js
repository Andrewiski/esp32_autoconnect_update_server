'use strict';
const http = require('http');
const https = require('https');
const debug = require('debug')('server');
const path = require('path');
const crypto = require('crypto');
const extend = require('extend');
const express = require('express');
const favicon = require('serve-favicon');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const fs = require('fs');
const moment = require('moment');
const fileUpload = require('express-fileupload');
const Deferred = require('node-promise').defer;
const util = require('util');
var configFileName = 'config/config.json';

var configFileSettings = {};
try {
    var strConfig = fs.readFileSync(path.join(__dirname, configFileName));
    configFileSettings = JSON.parse(strConfig);
} catch (ex) {
    //This needs to stay Console.log as writetolog will not function as no config
    console.log("error", "Error Reading Config File", ex);
}

var defaultOptions = {
    "logLevel": "info",
    "useHttp": true,
    "useHttps": false,
    "useHttpsClientCertAuth": false,
    "httpsServerKey": "config/server.key",
    "httpsServerCert": "config/server.cert",
    "httpsServerCa": "config/ca.cert",
    "httpport": 1336,
    "httpsport": 1337,
    "adminUsername": "admin",
    "adminPassword": "b8e422413690d73d18827474776b3a49",
    "autoconnectCatalogPath": "/_catalog",
    "adminDashboardPath":"/adminDashboard"
};

var objOptions = extend({}, defaultOptions, configFileSettings);

var startupReady = Deferred();

var isObject = function (a) {
    return (!!a) && (a.constructor === Object);
};

var isArray = function (a) {
    return (!!a) && (a.constructor === Array);
};

var arrayPrint = function (obj) {
    var retval = '';
    var i;
    for (i = 0; i < obj.length; i++) {
        if (retval.length > 0) {
            retval = retval + ', ';
        }
        retval = retval + objPrint(obj[i]);
    }

    return retval;
};

var objPrint = function (obj) {


    if (obj === null) {
        return 'null';
    } else if (obj === undefined) {
        return 'undefined';
    } else if (isArray(obj)) {
        return arrayPrint(obj);
    } else if (isObject(obj)) {
        return JSON.stringify(obj);
    } else {
        return obj.toString();
    }

};



var logLevels = {
    'quiet': -8, //Show nothing at all; be silent.
    'panic': 0, //Only show fatal errors which could lead the process to crash, such as an assertion failure.This is not currently used for anything.
    'fatal': 8, //Only show fatal errors.These are errors after which the process absolutely cannot continue.
    'error': 16, //Show all errors, including ones which can be recovered from.
    'warning': 24, //Show all warnings and errors.Any message related to possibly incorrect or unexpected events will be shown.
    'info': 32, //Show informative messages during processing.This is in addition to warnings and errors.This is the default value.
    'verbose': 40,  //Same as info, except more verbose.
    'debug': 48, //Show everything, including debugging information.
    'trace': 56
};


var writeToLog = function (logLevel) {
    try {
        let args = JSON.parse(JSON.stringify(arguments));
        if (args.length > 1) {
            args.shift(); //remove the loglevel from the array
        }
        let logData = { timestamp: new Date(), logLevel: logLevel, args: args };
        if (shouldLog(logLevel, objOptions.logLevel) === true) {



            //add to the top of the
            privateData.logs.push(logData);

            if (privateData.logs.length > objOptions.maxLogLength) {
                privateData.logs.shift();
            }

            //let winstonLogLevel = logLevel;
            //switch (logLevel) {
            //    case "panic":
            //    case "fatal":
            //        winstonLogLevel = "error";
            //        break;
            //    case "warning":
            //        winstonLogLevel = "warn";
            //        break;
            //    case "verbose":
            //        winstonLogLevel = "debug";
            //        break;
            //    case "trace":
            //        winstonLogLevel = "silly";
            //        break;
            //}
            //streamerlog.log({ timestamp: new Date(), level: winstonLogLevel, message: args });

            debug(arrayPrint(arguments));
            //debug(arguments[0], arguments[1]);  // attempt to make a one line log entry
            //if (objOptions.loglevel === 'trace') {
            //    console.log(arguments);
            //}
        }
        if (io && privateData.browserSockets) {
            for (const item of Object.values(privateData.browserSockets)) {
                if (shouldLog(logLevel, item.logLevel)) {
                    item.socket.emit("streamerLog", logData);
                }
            }
        }
    } catch (ex) {
        debug('error', 'Error WriteToLog', ex);
    }
};

var getLogLevel = function (logLevelName) {

    if (logLevels[logLevelName]) {
        return logLevels[logLevelName];
    } else {
        return 100;
    }
};



var shouldLog = function (logLevelName, logLevel) {

    if (getLogLevel(logLevelName) <= getLogLevel(logLevel)) {
        return true;
    } else {
        return false;
    }
};

var app = express();

var commonData = {
    logins: {}
};
var privateData = {
    logs: [],
    browserSockets: {}
};

var getConnectionInfo = function (req) {
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    if (ip.substr(0, 7) === "::ffff:") {
        ip = ip.substr(7);
    }
    var port = req.connection.remotePort;
    var ua = req.headers['user-agent'];
    return { ip: ip, port: port, ua: ua };
};


var getSocketInfo = function (socket) {
    var ip = socket.handshake.headers['x-forwarded-for'] || socket.conn.remoteAddress;
    if (ip.substr(0, 7) === "::ffff:") {
        ip = ip.substr(7);
    }

    return { ip: ip };
};

if (fs.existsSync(path.join(__dirname, 'log')) === false) {
    fs.mkdirSync(path.join(__dirname, 'log'));
}

var get_MD5 = function (filePath) {
    let file_buffer = fs.readFileSync(filePath);
    let sum = crypto.createHash('md5');
    sum.update(file_buffer);
    const hex = sum.digest('hex');
    return hex;
};


function basicAuth(req, res, next) {
    // make authenticate path public
    if (req.path === objOptions.autoconnectCatalogPath) {
        return next();
    }

    const realm = "AutoConnectUpdateServer";
    // check for basic auth header
    if (!req.headers.authorization || req.headers.authorization.indexOf('Basic ') === -1) {
        res.set('WWW-Authenticate', 'Basic realm="' + realm + '"');
        return res.status(401).json({ message: 'Missing Authorization Header' });
    }

    // verify auth credentials
    const base64Credentials = req.headers.authorization.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [username, password] = credentials.split(':');
    var connInfo = getConnectionInfo(req);

    let isvalidUserPass = checkUser(username, password, connInfo.ip, true);
    if (!isvalidUserPass.success) {
        if (io) {
            io.emit('logins', commonData.logins);
        }
        if (!isvalidUserPass.isAccountLocked) {
            res.set('WWW-Authenticate', 'Basic realm="' + realm + '"');
        }
        return res.status(401).json(isvalidUserPass);
    }

    // attach user to request object
    req.user = username;

    next();
}

function checkUser(username, password, ipAddress, resetLoginFailedIfSuccess) {
    const accountLockFailedAttempts = 5;
    const accountLockMinutes = 5;
    let passwordHash = crypto.createHash('md5').update(password).digest("hex");
    let isvalidUserPass = username.toLowerCase() === objOptions.adminUsername.toLowerCase() && passwordHash === objOptions.adminPasswordHash;
    let msg = "success";
    let isAccountLocked = false;
    if (username.toLowerCase() !== objOptions.adminUsername.toLowerCase()) {
        writeToLog('warning', 'login', 'Invalid username ', username);
        msg = "Invalid Username/Password";
    }

    //prevent Brute Force
    if (commonData.logins[username.toLowerCase()] && commonData.logins[username.toLowerCase()].ipaddresses[ipAddress] && commonData.logins[username.toLowerCase()].ipaddresses[ipAddress].failedLoginCount > accountLockFailedAttempts && moment().diff(commonData.logins[username.toLowerCase()].ipaddresses[ipAddress].failedLoginTimeStamp, 'minutes') < accountLockMinutes) {

        isAccountLocked = true;
    }
    if (commonData.logins[username.toLowerCase()] === undefined) {
        commonData.logins[username.toLowerCase()] = {
            ipaddresses: {}
        };
    }
    if (commonData.logins[username.toLowerCase()].ipaddresses[ipAddress] === undefined) {
        commonData.logins[username.toLowerCase()].ipaddresses[ipAddress] = {
            failedLoginCount: 0
        };
    }
    if ((isvalidUserPass === false || isAccountLocked === true) && username.toLowerCase() === objOptions.adminUsername.toLowerCase()) {
        commonData.logins[username.toLowerCase()].ipaddresses[ipAddress].failedLoginTimeStamp = moment();
        commonData.logins[username.toLowerCase()].ipaddresses[ipAddress].failedLoginCount++;


        if (isAccountLocked === true) {
            msg = "User Account is locked for " + accountLockMinutes.toString() + " minutes";
        } else {
            msg = "Invalid Username/Password";
        }
        writeToLog('warning', 'login', msg, "username:" + username + ", ip:" + ipAddress + ", isAccountLocked:" + isAccountLocked);
    } else {
        msg = "success";
        if (resetLoginFailedIfSuccess === true) {
            commonData.logins[username.toLowerCase()].ipaddresses[ipAddress].failedLoginCount = 0;
        }
    }

    return { success: isvalidUserPass && !isAccountLocked, username: username, msg: msg, isAccountLocked: isAccountLocked };
}

app.use(function (req, res, next) {
    var connInfo = getConnectionInfo(req);
    writeToLog('info', util.format('access to page:%s ip:%s port:%s ua:%s', req.path, connInfo.ip, connInfo.port, connInfo.ua));
    next();
});

app.use(express.static(path.join(__dirname, 'public')));

// disable the x-power-by express message in the header
app.disable('x-powered-by');
//app.use(basicAuth);

// not needed already served up by io app.use('/javascript/socket.io', express.static(path.join(__dirname, 'node_modules', 'socket.io', 'node_modules', 'socket.io-client', 'dist')));
app.use('/javascript/fontawesome', express.static(path.join(__dirname, 'node_modules', 'font-awesome')));
app.use('/javascript/bootstrap', express.static(path.join(__dirname, 'node_modules', 'bootstrap', 'dist')));
app.use('/javascript/jquery', express.static(path.join(__dirname, 'node_modules', 'jquery', 'dist')));
app.use('/javascript/moment', express.static(path.join(__dirname, 'node_modules', 'moment', 'min')));
app.use('/javascript/bootstrap-notify', express.static(path.join(__dirname, 'node_modules', 'bootstrap-notify')));
app.use('/javascript/animate-css', express.static(path.join(__dirname, 'node_modules', 'animate.css')));
app.use(favicon(__dirname + '/public/favicon.ico'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

app.use(fileUpload({
    limits: { fileSize: 50 * 1024 * 1024 },
}));




var routes = express.Router();
app.use('/', routes);
routes.get('/', function (req, res) {
    var connInfo = getConnectionInfo(req);
    res.end();
    writeToLog('info', "browser", "path:" + req.path + ", ip:" + connInfo.ip + ", port:" + connInfo.port + ", ua:" + connInfo.ua);
});


routes.get('/updates/*', function (req, res) {
    try {
        var connInfo = getConnectionInfo(req);
        writeToLog('info', "browser", "path:" + req.path + ", ip:" + connInfo.ip + ", port:" + connInfo.port + ", ua:" + connInfo.ua);

        let folderPath = path.dirname(req.path);
        let fileName = path.basename(req.path);
        if (fs.existsSync(path.join(__dirname, folderPath, fileName)) === true) {
            let fileStat = fs.statSync(path.join(__dirname, folderPath, fileName));
            var options = {
                root: path.join(__dirname, folderPath),
                dotfiles: 'deny',
                headers: {
                    'Content-Type': 'application/octet-stream',
                    'Content-Disposition': 'attachment; filename=' + fileName,
                    'Content-Length': fileStat.size,
                    'x-MD5': get_MD5(path.join(__dirname, folderPath, fileName))
                }
            };
            res.sendFile( fileName, options, function (err) {
                if (err) {
                    writeToLog('error', 'Error Sending Update file', path.join(folderPath, fileName));
                    res.status(500).send("Error Sending Update File " + ex.message);
                    //next(err);
                } else {
                    writeToLog('info', 'Sent update file', path.join(folderPath, fileName));
                }
            });
        } else {
            res.status(404).send("File Not Found Andy");
        }
    } catch (ex) {
        res.status(500).send("Error Sending File " + ex.message);
    }
});



routes.get(objOptions.autoconnectCatalogPath, function (req, res) {

    var connInfo = getConnectionInfo(req);
    writeToLog('info', "browser", "path:" + req.path + ", ip:" + connInfo.ip + ", port:" + connInfo.port + ", ua:" + connInfo.ua);

    let folderPath = req.query.path;

    let files = fs.readdirSync(path.join(__dirname, folderPath), { withFileTypes: true });
    let catalog = [];
    files.forEach(function (fileInfo) {
        try {
            if (fileInfo.isFile() === true && path.extname(fileInfo.name) === '.bin') {
                let fileStat = fs.statSync(path.join(__dirname, folderPath, fileInfo.name));
                catalog.push({
                    "name": fileInfo.name,
                    "type": "bin",
                    "date": moment(fileStat.mtime).format("MM/DD/YYYY"),
                    "time": moment(fileStat.mtime).format("hh:mm:ss"),
                    "size": fileStat.size
                });
            }
        } catch (ex) {
            writeToLog('error', 'Error reading folder', folderPath, fileInfo.name, ex);
        }

    });
    
    res.status(200).send(catalog);
});


routes.post('/certificateUpload', function (req, res) {
    //Route that the Https Certs are uploaded to
    try {
        if (!req.files) {
            res.send({
                success: false,
                status: 'failed',
                message: 'No file uploaded'
            });
        } else {

            let privateKeyFile = req.files.PrivateKeyFile;
            //privateKeyFile.mv(path.join(__dirname, options.httpsServerKey));

            let publicCertFile = req.files.PublicCertFile;
            //publicCertFile.mv(path.join(__dirname, options.httpsServerCert));

            loadX509PublicCert({ publicCertFile: publicCertFile.data, privateKeyFile: privateKeyFile.data }).then(
                function (certs) {
                    try {
                        if (certs) {

                            var hasValidPrivateKey = false;
                            certs.forEach(function (cert) {
                                if (cert.privateKeyValid) {
                                    hasValidPrivateKey = true;
                                }
                            });

                            if (hasValidPrivateKey === true) {
                                if (fs.existsSync(path.join(__dirname, objOptions.httpsServerKey))) {
                                    if (fs.existsSync(path.join(__dirname, path.dirname(objOptions.httpsServerKey), 'backups')) === false) {
                                        fs.mkdirSync(path.join(__dirname, path.dirname(objOptions.httpsServerKey), 'backups'));
                                    }
                                    fs.copyFileSync(path.join(__dirname, objOptions.httpsServerKey), path.join(__dirname, path.dirname(objOptions.httpsServerKey), 'backups', moment().format("YYYYMMDDhhmmss") + '_' + path.basename(objOptions.httpsServerKey)));
                                }

                                if (fs.existsSync(path.join(__dirname, objOptions.httpsServerCert))) {
                                    if (fs.existsSync(path.join(__dirname, path.dirname(objOptions.httpsServerCert), 'backups')) === false) {
                                        fs.mkdirSync(path.join(__dirname, path.dirname(objOptions.httpsServerCert), 'backups'));
                                    }
                                    fs.copyFileSync(path.join(__dirname, objOptions.httpsServerCert), path.join(__dirname, path.dirname(objOptions.httpsServerCert), 'backups', moment().format("YYYYMMDDhhmmss") + '_' + path.basename(objOptions.httpsServerCert)));
                                }
                                fs.writeFileSync(path.join(__dirname, objOptions.httpsServerKey), privateKeyFile.data);
                                fs.writeFileSync(path.join(__dirname, objOptions.httpsServerCert), publicCertFile.data);
                                //send response
                                res.send({
                                    success: true,
                                    status: "complete",
                                    message: 'Certificate Files uploaded',
                                    data: {
                                        privateKeyFile:
                                        {
                                            name: privateKeyFile.name,
                                            mimetype: privateKeyFile.mimetype,
                                            size: privateKeyFile.size
                                        },
                                        publicCertFile:
                                        {
                                            name: publicCertFile.name,
                                            mimetype: publicCertFile.mimetype,
                                            size: publicCertFile.size
                                        }
                                    }
                                });
                                //update the https server so it uses the new certs
                                updateHttpsServer();
                            } else {
                                res.send({
                                    success: false,
                                    status: "Error",
                                    message: 'Private Key is not valid for Certificate',
                                    data: {
                                        privateKeyFile:
                                        {
                                            name: privateKeyFile.name,
                                            mimetype: privateKeyFile.mimetype,
                                            size: privateKeyFile.size
                                        },
                                        publicCertFile:
                                        {
                                            name: publicCertFile.name,
                                            mimetype: publicCertFile.mimetype,
                                            size: publicCertFile.size
                                        }
                                    }
                                });
                            }
                        }
                    } catch (err) {
                        res.status(500).send({
                            success: false,
                            status: "Error",
                            message: err,
                            data: null
                        });
                    }
                },
                function (ev, message) {
                    res.status(500).send({
                        success: false,
                        status: ev,
                        message: message,
                        data: null
                    });
                }


            );



        }
    } catch (err) {
        res.status(500).send({
            success: false,
            status: "Error",
            message: err,
            data: null
        });
    }
});

routes.get(objOptions.adminDashboardPath, function (req, res) {
    var connInfo = getConnectionInfo(req);

    writeToLog('info', "browser", "admintool", "connect", "ip: " + connInfo.ip + ", port: " + connInfo.port + ", ua:" + connInfo.ua);

    if (objOptions.useHttpsClientCertAuth) {
        const cert = req.connection.getPeerCertificate();
        if (req.client.authorized) {
            writeToLog('info', `Client Certificate Accepted ${cert.subject.CN}, certificate was issued by ${cert.issuer.CN}!`);
            res.sendFile(path.join(__dirname, 'admin/index.htm'));
        } else if (cert.subject) {
            writeToLog('warning', `Invalid Client Certificate ${cert.subject.CN}, certificate was issued by ${cert.issuer.CN}!`);
            res.status(403).send(`Sorry ${cert.subject.CN}, certificates from ${cert.issuer.CN} are not welcome here.`);
        } else {
            writeToLog('warning', 'Client Cert Auth Enabled but no Certificate was sent by client');
            res.status(401).send(`Sorry, but you need to provide a client certificate to continue.`);
        }
    } else {
        res.sendFile(path.join(__dirname, 'admin/admin.htm'));
    }
});


const ioServer = require('socket.io');
var io = null;
//Only Wire up Admin Page and ??

io = new ioServer();

var https_srv = null;
var http_srv = null;

var getHttpsServerOptions = function () {
    //We share the https cert with both Client https and Management https
    //We share the https cert with both Client https and Management https
    var httpsOptions = {
        key: fs.readFileSync(path.join(__dirname, objOptions.httpsServerKey)),
        cert: fs.readFileSync(path.join(__dirname, objOptions.httpsServerCert))
    };

    if (objOptions.useHttpsClientCertAuth) {
        if (objOptions.httpsServerCa) {
            httpsOptions.ca = fs.readFileSync(path.join(__dirname, objOptions.httpsClientAuthCaCert));
        }
        httpsOptions.requestCert = true;
        httpsOptions.rejectUnauthorized = false;
    }
    return httpsOptions;
};

var startWebServers = function () {

    if (objOptions.useHttps === true) {

        https_srv = https.createServer(getHttpsServerOptions(), app).listen(objOptions.httpsport, function () {
            writeToLog('info', 'Express server listening on https port ' + objOptions.httpsport);
            console.log('Express server listening on https port ' + objOptions.httpsport);
        });
        io.attach(https_srv);
    }


    if (objOptions.useHttp === true) {
        http_srv = http.createServer(app).listen(objOptions.httpport, function () {
            writeToLog('info', 'Express server listening on http port ' + objOptions.httpport);
            console.log('Express server listening on http port ' + objOptions.httpport);
        });
        io.attach(http_srv);
    }
};


var updateHttpsServer = function () {
    try {
        https_srv.setSecureContext(getHttpsServerOptions());
    } catch (ex) {
        writeToLog("error", "Error Updating https server with new security context", ex);
    }
};


// This is the socket io for the local Admin page

//io = require('socket.io')(https_srv);
io.on('connection', function (socket) {


    writeToLog('info', 'browser', socket.id, 'Connection', getSocketInfo(socket));

    const base64Credentials = socket.conn.request.headers.authorization.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [username, password] = credentials.split(':');

    var validUser = checkUser(username, password, getSocketInfo(socket).ip, false);

    if (validUser.success === false) {
        socket.emit('authenticated', validUser);
        socket.disconnect();
    } else {
        socket.emit('authenticated', validUser);
        if (privateData.browserSockets[socket.id] === undefined) {
            privateData.browserSockets[socket.id] = {
                socket: socket,
                logLevel: objOptions.logLevel

            };
        }

        socket.on('ping', function (data) {
            writeToLog('trace', 'browser', socket.id, 'ping');
        });

        socket.on("disconnect", function () {
            try {
                writeToLog("info", 'browser', socket.id, "disconnect", getSocketInfo(socket));
                if (privateData.browserSockets[socket.id]) {
                    delete privateData.browserSockets[socket.id];
                }
            } catch (ex) {
                writeToLog('error', 'Error socket on', ex);
            }
        });

       

        //This is a new connection, so send info to commonData
        socket.emit('commonData', commonData);
        
    }
});



var startupServer = function () {
    try {
        startWebServers();
    } catch (ex) {
        writeToLog('error', 'Error Starting Web Servers', ex);
    }
};

//we use this defer to delay start to wait on a mongo load of data on startup to get data and keep everything in sync
var startupPromise = startupReady.promise;
startupPromise.then(startupServer);

startupReady.resolve();
//console.log("pwd hash", crypto.createHash('md5').update('autoconnect').digest("hex"));