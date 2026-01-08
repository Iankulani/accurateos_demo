"use strict";
/**
 * ACCURATE ONLINE OS DEMO - ENHANCED VERSION
 * Author: Ian Carter Kulani
 * Version: Demo
 * TypeScript Version
 */
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TelegramBotHandler = exports.TracerouteTool = exports.DatabaseManager = exports.NetworkScanner = exports.CybersecurityMonitor = void 0;
var net = require("net");
var dns = require("dns");
var os = require("os");
var fs = require("fs");
var path = require("path");
var child_process_1 = require("child_process");
var readline = require("readline");
var perf_hooks_1 = require("perf_hooks");
// External dependencies (install with npm install)
var axios;
var sqlite3;
var geoip;
var ping;
var whois;
var si;
var nmap;
var NMAP_AVAILABLE = false;
// Try to load dependencies
try {
    axios = require('axios');
}
catch (e) {
    console.log("Warning: axios not available. Install with: npm install axios");
}
try {
    sqlite3 = require('sqlite3').verbose();
}
catch (e) {
    console.log("Warning: sqlite3 not available. Install with: npm install sqlite3");
}
try {
    geoip = require('geoip-lite');
}
catch (e) {
    console.log("Warning: geoip-lite not available. Install with: npm install geoip-lite");
}
try {
    ping = require('ping');
}
catch (e) {
    console.log("Warning: ping not available. Install with: npm install ping");
}
try {
    whois = require('whois-json');
}
catch (e) {
    console.log("Warning: whois-json not available. Install with: npm install whois-json");
}
try {
    si = require('systeminformation');
}
catch (e) {
    console.log("Warning: systeminformation not available. Install with: npm install systeminformation");
}
try {
    nmap = require('node-nmap');
    NMAP_AVAILABLE = true;
}
catch (e) {
    console.log("Warning: node-nmap not available. Install with: npm install node-nmap");
}
// Configuration
var CONFIG_FILE = "cyber_security_config.json";
var DATABASE_FILE = "network_data.db";
var REPORT_DIR = "reports";
var TracerouteTool = /** @class */ (function () {
    function TracerouteTool() {
    }
    /** Enhanced interactive traceroute tool */
    TracerouteTool.isIPv4OrIPv6 = function (address) {
        /** Check if input is valid IPv4 or IPv6 address */
        // Simple IPv4 regex
        var ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        // Simple IPv6 regex
        var ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
        return ipv4Regex.test(address) || ipv6Regex.test(address);
    };
    TracerouteTool.isValidHostname = function (name) {
        /** Check if input is valid hostname */
        var hostname = name;
        if (hostname.endsWith('.')) {
            hostname = hostname.slice(0, -1);
        }
        // Hostname validation regex
        var HOSTNAME_RE = /^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$/;
        return HOSTNAME_RE.test(hostname);
    };
    TracerouteTool.chooseTracerouteCmd = function (target) {
        /** Return appropriate traceroute command for the system */
        var platform = os.platform();
        if (platform === 'win32') {
            return ['tracert', '-d', target];
        }
        // On Unix-like systems
        // Check for traceroute utilities
        return ['traceroute', '-n', '-q', '1', '-w', '2', target];
    };
    TracerouteTool.streamSubprocess = function (cmd) {
        /** Run subprocess and capture output */
        return new Promise(function (resolve) {
            var outputLines = [];
            var startTime = perf_hooks_1.performance.now();
            var proc = (0, child_process_1.spawn)(cmd[0], cmd.slice(1));
            proc.stdout.on('data', function (data) {
                var line = data.toString().trim();
                outputLines.push(line);
                console.log(line);
            });
            proc.stderr.on('data', function (data) {
                var line = data.toString().trim();
                outputLines.push(line);
                console.log(line);
            });
            proc.on('close', function (code) {
                var executionTime = (perf_hooks_1.performance.now() - startTime) / 1000;
                resolve({
                    returncode: code,
                    output: outputLines.join('\n'),
                    executionTime: executionTime
                });
            });
            proc.on('error', function (err) {
                var errorMsg = "[!] Error running command: ".concat(err.message);
                console.log(errorMsg);
                outputLines.push(errorMsg);
                resolve({
                    returncode: -2,
                    output: outputLines.join('\n'),
                    executionTime: (perf_hooks_1.performance.now() - startTime) / 1000
                });
            });
        });
    };
    TracerouteTool.prototype.interactiveTraceroute = function () {
        return __awaiter(this, arguments, void 0, function (target) {
            var cmd, _a, returncode, output, executionTime, result;
            if (target === void 0) { target = null; }
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        if (!!target) return [3 /*break*/, 2];
                        return [4 /*yield*/, this.promptTarget()];
                    case 1:
                        target = _b.sent();
                        if (!target) {
                            return [2 /*return*/, "Traceroute cancelled."];
                        }
                        _b.label = 2;
                    case 2:
                        // Validate target
                        if (!(TracerouteTool.isIPv4OrIPv6(target) || TracerouteTool.isValidHostname(target))) {
                            return [2 /*return*/, "\u274C Invalid IP address or hostname: ".concat(target)];
                        }
                        try {
                            cmd = TracerouteTool.chooseTracerouteCmd(target);
                        }
                        catch (e) {
                            return [2 /*return*/, "\u274C Traceroute error: ".concat(e.message)];
                        }
                        console.log("Running: ".concat(cmd.join(' '), "\n"));
                        return [4 /*yield*/, TracerouteTool.streamSubprocess(cmd)];
                    case 3:
                        _a = _b.sent(), returncode = _a.returncode, output = _a.output, executionTime = _a.executionTime;
                        result = "\uD83D\uDEE3\uFE0F <b>Traceroute to ".concat(target, "</b>\n\n");
                        result += "Command: <code>".concat(cmd.join(' '), "</code>\n");
                        result += "Execution time: ".concat(executionTime.toFixed(2), "s\n");
                        result += "Return code: ".concat(returncode, "\n\n");
                        // Limit output
                        if (output.length > 3000) {
                            result += "<code>".concat(output.slice(-3000), "</code>");
                        }
                        else {
                            result += "<code>".concat(output, "</code>");
                        }
                        return [2 /*return*/, result];
                }
            });
        });
    };
    TracerouteTool.prototype.promptTarget = function () {
        return __awaiter(this, void 0, void 0, function () {
            var rl;
            return __generator(this, function (_a) {
                rl = readline.createInterface({
                    input: process.stdin,
                    output: process.stdout
                });
                return [2 /*return*/, new Promise(function (resolve) {
                        var ask = function () {
                            rl.question('Enter target IP address or hostname to traceroute (or type "quit" to exit): ', function (userInput) {
                                var input = userInput.trim();
                                if (!input) {
                                    console.log('Please enter a non-empty value.');
                                    ask();
                                    return;
                                }
                                if (input.toLowerCase() === 'q' || input.toLowerCase() === 'quit' || input.toLowerCase() === 'exit') {
                                    rl.close();
                                    resolve(null);
                                    return;
                                }
                                if (TracerouteTool.isIPv4OrIPv6(input) || TracerouteTool.isValidHostname(input)) {
                                    rl.close();
                                    resolve(input);
                                }
                                else {
                                    console.log('Invalid IP address or hostname. Examples: 8.8.8.8, 2001:4860:4860::8888, example.com');
                                    ask();
                                }
                            });
                        };
                        ask();
                    })];
            });
        });
    };
    return TracerouteTool;
}());
exports.TracerouteTool = TracerouteTool;
var DatabaseManager = /** @class */ (function () {
    function DatabaseManager() {
        this.dbFile = DATABASE_FILE;
        this.initDatabase();
    }
    DatabaseManager.prototype.initDatabase = function () {
        /** Initialize database tables */
        var db = new sqlite3.Database(this.dbFile);
        db.serialize(function () {
            // IP monitoring table
            db.run("\n                CREATE TABLE IF NOT EXISTS monitored_ips (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    ip_address TEXT UNIQUE NOT NULL,\n                    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n                    is_active BOOLEAN DEFAULT 1,\n                    threat_level INTEGER DEFAULT 0,\n                    last_scan TIMESTAMP\n                )\n            ");
            // Threat detection table
            db.run("\n                CREATE TABLE IF NOT EXISTS threat_logs (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    ip_address TEXT NOT NULL,\n                    threat_type TEXT NOT NULL,\n                    severity TEXT NOT NULL,\n                    description TEXT,\n                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n                    resolved BOOLEAN DEFAULT 0\n                )\n            ");
            // Command history table
            db.run("\n                CREATE TABLE IF NOT EXISTS command_history (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    command TEXT NOT NULL,\n                    source TEXT DEFAULT 'local',\n                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n                    success BOOLEAN DEFAULT 1\n                )\n            ");
            // Network scan results table
            db.run("\n                CREATE TABLE IF NOT EXISTS scan_results (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    ip_address TEXT NOT NULL,\n                    scan_type TEXT NOT NULL,\n                    open_ports TEXT,\n                    services TEXT,\n                    os_info TEXT,\n                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n                )\n            ");
            // Traceroute results table
            db.run("\n                CREATE TABLE IF NOT EXISTS traceroute_results (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    target TEXT NOT NULL,\n                    command TEXT NOT NULL,\n                    output TEXT,\n                    execution_time REAL,\n                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n                )\n            ");
        });
        db.close();
    };
    DatabaseManager.prototype.logCommand = function (command, source, success) {
        var _this = this;
        if (source === void 0) { source = 'local'; }
        if (success === void 0) { success = true; }
        /** Log command to database */
        return new Promise(function (resolve, reject) {
            var db = new sqlite3.Database(_this.dbFile);
            db.run('INSERT INTO command_history (command, source, success) VALUES (?, ?, ?)', [command, source, success ? 1 : 0], function (err) {
                if (err)
                    reject(err);
                else
                    resolve();
                db.close();
            });
        });
    };
    DatabaseManager.prototype.logTraceroute = function (target, command, output, executionTime) {
        var _this = this;
        /** Log traceroute results to database */
        return new Promise(function (resolve, reject) {
            var db = new sqlite3.Database(_this.dbFile);
            db.run('INSERT INTO traceroute_results (target, command, output, execution_time) VALUES (?, ?, ?, ?)', [target, command, output, executionTime], function (err) {
                if (err)
                    reject(err);
                else
                    resolve();
                db.close();
            });
        });
    };
    DatabaseManager.prototype.getCommandHistory = function (limit) {
        var _this = this;
        if (limit === void 0) { limit = 50; }
        /** Get command history from database */
        return new Promise(function (resolve, reject) {
            var db = new sqlite3.Database(_this.dbFile);
            db.all('SELECT command, source, timestamp, success FROM command_history ORDER BY timestamp DESC LIMIT ?', [limit], function (err, rows) {
                if (err)
                    reject(err);
                else
                    resolve(rows);
                db.close();
            });
        });
    };
    DatabaseManager.prototype.logThreat = function (ipAddress, threatType, severity, description) {
        var _this = this;
        if (description === void 0) { description = ""; }
        /** Log threat detection to database */
        return new Promise(function (resolve, reject) {
            var db = new sqlite3.Database(_this.dbFile);
            db.run('INSERT INTO threat_logs (ip_address, threat_type, severity, description) VALUES (?, ?, ?, ?)', [ipAddress, threatType, severity, description], function (err) {
                if (err)
                    reject(err);
                else
                    resolve();
                db.close();
            });
        });
    };
    DatabaseManager.prototype.getRecentThreats = function (limit) {
        var _this = this;
        if (limit === void 0) { limit = 20; }
        /** Get recent threats from database */
        return new Promise(function (resolve, reject) {
            var db = new sqlite3.Database(_this.dbFile);
            db.all('SELECT ip_address, threat_type, severity, timestamp FROM threat_logs ORDER BY timestamp DESC LIMIT ?', [limit], function (err, rows) {
                if (err)
                    reject(err);
                else
                    resolve(rows);
                db.close();
            });
        });
    };
    DatabaseManager.prototype.getMonitoredIPs = function () {
        var _this = this;
        /** Get all monitored IPs */
        return new Promise(function (resolve, reject) {
            var db = new sqlite3.Database(_this.dbFile);
            db.all('SELECT ip_address FROM monitored_ips WHERE is_active = 1', function (err, rows) {
                if (err)
                    reject(err);
                else
                    resolve(rows.map(function (row) { return row.ip_address; }));
                db.close();
            });
        });
    };
    DatabaseManager.prototype.addMonitoredIP = function (ip) {
        var _this = this;
        /** Add IP to monitoring list */
        return new Promise(function (resolve, reject) {
            var db = new sqlite3.Database(_this.dbFile);
            db.run('INSERT OR REPLACE INTO monitored_ips (ip_address, is_active) VALUES (?, 1)', [ip], function (err) {
                if (err)
                    reject(err);
                else
                    resolve();
                db.close();
            });
        });
    };
    DatabaseManager.prototype.removeMonitoredIP = function (ip) {
        var _this = this;
        /** Remove IP from monitoring list */
        return new Promise(function (resolve, reject) {
            var db = new sqlite3.Database(_this.dbFile);
            db.run('UPDATE monitored_ips SET is_active = 0 WHERE ip_address = ?', [ip], function (err) {
                if (err)
                    reject(err);
                else
                    resolve();
                db.close();
            });
        });
    };
    return DatabaseManager;
}());
exports.DatabaseManager = DatabaseManager;
var NetworkScanner = /** @class */ (function () {
    function NetworkScanner() {
        this.tracerouteTool = new TracerouteTool();
    }
    NetworkScanner.prototype.pingIP = function (ip) {
        return __awaiter(this, void 0, void 0, function () {
            var result, error_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        /** Simple ping */
                        if (!ping) {
                            return [2 /*return*/, "Ping utility not available. Install with: npm install ping"];
                        }
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 3, , 4]);
                        return [4 /*yield*/, ping.promise.probe(ip, {
                                timeout: 10,
                                extra: ['-c', '4']
                            })];
                    case 2:
                        result = _a.sent();
                        return [2 /*return*/, result.alive ?
                                "Ping ".concat(ip, ": alive\nRound-trip time: ").concat(result.time, "ms") :
                                "Ping ".concat(ip, ": unreachable")];
                    case 3:
                        error_1 = _a.sent();
                        return [2 /*return*/, "Ping error: ".concat(error_1.message)];
                    case 4: return [2 /*return*/];
                }
            });
        });
    };
    NetworkScanner.prototype.traceroute = function (target) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.tracerouteTool.interactiveTraceroute(target)];
                    case 1: 
                    /** Perform enhanced traceroute */
                    return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    NetworkScanner.prototype.portScan = function (ip_1) {
        return __awaiter(this, arguments, void 0, function (ip, ports) {
            var scan_1;
            if (ports === void 0) { ports = "1-1000"; }
            return __generator(this, function (_a) {
                /** Perform port scan */
                if (!NMAP_AVAILABLE) {
                    return [2 /*return*/, { success: false, error: 'Nmap not available' }];
                }
                try {
                    scan_1 = new nmap.NmapScan(ip, ports);
                    return [2 /*return*/, new Promise(function (resolve) {
                            scan_1.on('complete', function (data) {
                                var openPorts = [];
                                if (data && data[0] && data[0].openPorts) {
                                    data[0].openPorts.forEach(function (port) {
                                        openPorts.push({
                                            port: port.port,
                                            state: port.state,
                                            service: port.service
                                        });
                                    });
                                }
                                resolve({
                                    success: true,
                                    target: ip,
                                    openPorts: openPorts,
                                    scanTime: new Date().toISOString()
                                });
                            });
                            scan_1.on('error', function (error) {
                                resolve({
                                    success: false,
                                    error: error.message
                                });
                            });
                            scan_1.startScan();
                        })];
                }
                catch (error) {
                    return [2 /*return*/, { success: false, error: error.message }];
                }
                return [2 /*return*/];
            });
        });
    };
    NetworkScanner.prototype.getIPLocation = function (ip) {
        return __awaiter(this, void 0, void 0, function () {
            var geo, response, error_2;
            var _a;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        _b.trys.push([0, 3, , 4]);
                        if (geoip) {
                            geo = geoip.lookup(ip);
                            if (geo) {
                                return [2 /*return*/, JSON.stringify({
                                        ip: ip,
                                        country: geo.country || 'N/A',
                                        region: geo.region || 'N/A',
                                        city: geo.city || 'N/A',
                                        ll: geo.ll || ['N/A', 'N/A'],
                                        metro: geo.metro || 'N/A',
                                        area: geo.area || 'N/A',
                                        range: geo.range || 'N/A'
                                    }, null, 2)];
                            }
                        }
                        if (!axios) return [3 /*break*/, 2];
                        return [4 /*yield*/, axios.get("http://ip-api.com/json/".concat(ip), { timeout: 10000 })];
                    case 1:
                        response = _b.sent();
                        if (response.data && response.data.status === 'success') {
                            return [2 /*return*/, JSON.stringify({
                                    ip: ip,
                                    country: response.data.country || 'N/A',
                                    region: response.data.regionName || 'N/A',
                                    city: response.data.city || 'N/A',
                                    isp: response.data.isp || 'N/A',
                                    org: response.data.org || 'N/A',
                                    lat: response.data.lat || 'N/A',
                                    lon: response.data.lon || 'N/A',
                                    timezone: response.data.timezone || 'N/A'
                                }, null, 2)];
                        }
                        else {
                            return [2 /*return*/, "Location error: ".concat(((_a = response.data) === null || _a === void 0 ? void 0 : _a.message) || 'Unknown error')];
                        }
                        _b.label = 2;
                    case 2: return [2 /*return*/, 'Location services not available'];
                    case 3:
                        error_2 = _b.sent();
                        return [2 /*return*/, "Location error: ".concat(error_2.message)];
                    case 4: return [2 /*return*/];
                }
            });
        });
    };
    NetworkScanner.prototype.whoisLookup = function (domain) {
        return __awaiter(this, void 0, void 0, function () {
            var result, error_3;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        /** WHOIS lookup */
                        if (!whois) {
                            return [2 /*return*/, 'WHOIS not available. Install with: npm install whois-json'];
                        }
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 3, , 4]);
                        return [4 /*yield*/, whois(domain)];
                    case 2:
                        result = _a.sent();
                        return [2 /*return*/, JSON.stringify(result, null, 2)];
                    case 3:
                        error_3 = _a.sent();
                        return [2 /*return*/, "WHOIS error: ".concat(error_3.message)];
                    case 4: return [2 /*return*/];
                }
            });
        });
    };
    return NetworkScanner;
}());
exports.NetworkScanner = NetworkScanner;
var TelegramBotHandler = /** @class */ (function () {
    function TelegramBotHandler(monitor) {
        this.lastUpdateId = 0;
        this.monitor = monitor;
        this.commandHandlers = this.setupCommandHandlers();
    }
    TelegramBotHandler.prototype.setupCommandHandlers = function () {
        /** Setup comprehensive command handlers */
        return {
            '/start': this.handleStart.bind(this),
            '/help': this.handleHelp.bind(this),
            '/ping_ip': this.handlePingIP.bind(this),
            '/start_monitoring_ip': this.handleStartMonitoringIP.bind(this),
            '/stop': this.handleStop.bind(this),
            '/history': this.handleHistory.bind(this),
            '/add_ip': this.handleAddIP.bind(this),
            '/remove_ip': this.handleRemoveIP.bind(this),
            '/list_ips': this.handleListIPs.bind(this),
            '/clear': this.handleClear.bind(this),
            '/tracert_ip': this.handleTracertIP.bind(this),
            '/traceroute_ip': this.handleTracerouteIP.bind(this),
            '/scan_ip': this.handleScanIP.bind(this),
            '/location_ip': this.handleLocationIP.bind(this),
            '/analyze_ip': this.handleAnalyzeIP.bind(this),
            '/status': this.handleStatus.bind(this),
            '/curl': this.handleCurl.bind(this),
            '/whois': this.handleWhois.bind(this),
            '/dns_lookup': this.handleDNSLookup.bind(this),
            '/network_info': this.handleNetworkInfo.bind(this),
            '/system_info': this.handleSystemInfo.bind(this),
            '/threat_summary': this.handleThreatSummary.bind(this),
            '/generate_report': this.handleGenerateReport.bind(this),
            '/advanced_traceroute': this.handleAdvancedTraceroute.bind(this)
        };
    };
    TelegramBotHandler.prototype.sendTelegramMessage = function (message_1) {
        return __awaiter(this, arguments, void 0, function (message, parseMode) {
            var url, messages, i, _i, messages_1, msg, payload, response, payload, response, error_4;
            if (parseMode === void 0) { parseMode = 'HTML'; }
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        /** Send message to Telegram */
                        if (!this.monitor.telegramToken || !this.monitor.telegramChatId) {
                            return [2 /*return*/, false];
                        }
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 10, , 11]);
                        url = "https://api.telegram.org/bot".concat(this.monitor.telegramToken, "/sendMessage");
                        if (!(message.length > 4096)) return [3 /*break*/, 7];
                        messages = [];
                        for (i = 0; i < message.length; i += 4096) {
                            messages.push(message.substring(i, i + 4096));
                        }
                        _i = 0, messages_1 = messages;
                        _a.label = 2;
                    case 2:
                        if (!(_i < messages_1.length)) return [3 /*break*/, 6];
                        msg = messages_1[_i];
                        payload = {
                            chat_id: this.monitor.telegramChatId,
                            text: msg,
                            parse_mode: parseMode,
                            disable_web_page_preview: true
                        };
                        return [4 /*yield*/, axios.post(url, payload, { timeout: 30000 })];
                    case 3:
                        response = _a.sent();
                        if (response.status !== 200) {
                            return [2 /*return*/, false];
                        }
                        return [4 /*yield*/, this.sleep(500)];
                    case 4:
                        _a.sent();
                        _a.label = 5;
                    case 5:
                        _i++;
                        return [3 /*break*/, 2];
                    case 6: return [2 /*return*/, true];
                    case 7:
                        payload = {
                            chat_id: this.monitor.telegramChatId,
                            text: message,
                            parse_mode: parseMode,
                            disable_web_page_preview: true
                        };
                        return [4 /*yield*/, axios.post(url, payload, { timeout: 30000 })];
                    case 8:
                        response = _a.sent();
                        return [2 /*return*/, response.status === 200];
                    case 9: return [3 /*break*/, 11];
                    case 10:
                        error_4 = _a.sent();
                        console.error("Telegram send error: ".concat(error_4.message));
                        return [2 /*return*/, false];
                    case 11: return [2 /*return*/];
                }
            });
        });
    };
    TelegramBotHandler.prototype.sleep = function (ms) {
        return new Promise(function (resolve) { return setTimeout(resolve, ms); });
    };
    TelegramBotHandler.prototype.handleStart = function (args) {
        /** Handle /start command */
        return "\n\uD83D\uDE80 <b>accurateOS Demo - Enhanced Edition v2</b> \uD83D\uDE80\n\nWelcome! Your cybersecurity assistant is ready.\n\n\uD83D\uDD0D <b>Network Commands</b>\n/ping_ip [IP] - Ping IP address\n/tracert_ip [IP] - Traceroute (Windows)\n/traceroute_ip [IP] - Traceroute (Linux/Mac)\n/advanced_traceroute [IP] - Enhanced traceroute\n/scan_ip [IP] - Port scan\n/location_ip [IP] - Get IP location\n/analyze_ip [IP] - Analyze IP threats\n/whois [domain] - WHOIS lookup\n/dns_lookup [domain] - DNS lookup\n\n\uD83D\uDCCA <b>Monitoring</b>\n/start_monitoring_ip [IP] - Start monitoring\n/stop - Stop all monitoring\n/add_ip [IP] - Add IP to list\n/remove_ip [IP] - Remove IP\n/list_ips - List monitored IPs\n/threat_summary - Recent threats\n\n\uD83D\uDCBB <b>System</b>\n/network_info - Network information\n/system_info - System information\n/status - System status\n/history - Command history\n/clear - Clear history\n\n\uD83D\uDCE1 <b>Web Tools</b>\n/curl [URL] - HTTP request\n/generate_report - Generate security report\n\n\u2753 Type /help for detailed usage!\n        ";
    };
    TelegramBotHandler.prototype.handleHelp = function (args) {
        /** Show help */
        return "\n<b>\uD83D\uDD12 Complete Command Reference</b>\n\n<b>\uD83C\uDF10 Network Diagnostics:</b>\n<code>/ping_ip 8.8.8.8</code>\n<code>/tracert_ip google.com</code>\n<code>/traceroute_ip example.com</code>\n<code>/advanced_traceroute 1.1.1.1</code>\n<code>/scan_ip 192.168.1.1</code>\n<code>/location_ip 1.1.1.1</code>\n<code>/whois malawi.com</code>\n<code>/dns_lookup example.com</code>\n\n<b>\uD83D\uDEE1\uFE0F Security Analysis:</b>\n<code>/analyze_ip 192.168.1.1</code>\n<code>/threat_summary</code>\n<code>/generate_report</code>\n\n<b>\uD83D\uDCCA Monitoring:</b>\n<code>/start_monitoring_ip 192.168.1.1</code>\n<code>/add_ip 10.0.0.1</code>\n<code>/remove_ip 10.0.0.1</code>\n<code>/list_ips</code>\n<code>/stop</code>\n\n<b>\uD83D\uDCBB System Info:</b>\n<code>/network_info</code>\n<code>/system_info</code>\n<code>/status</code>\n\n<b>\uD83C\uDF0D Web Tools:</b>\n<code>/curl https://api.github.com</code>\n\nAll commands execute instantly! \uD83D\uDE80\n        ";
    };
    TelegramBotHandler.prototype.handlePingIP = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var ip, result, preview;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        /** Handle ping */
                        if (!args || args.length === 0) {
                            return [2 /*return*/, "❌ Usage: <code>/ping_ip [IP]</code>"];
                        }
                        ip = args[0];
                        return [4 /*yield*/, this.monitor.scanner.pingIP(ip)];
                    case 1:
                        result = _a.sent();
                        preview = result.length > 1000 ? result.substring(result.length - 1000) : result;
                        return [2 /*return*/, "\uD83C\uDFD3 <b>Ping ".concat(ip, "</b>\n\n<code>").concat(preview, "</code>")];
                }
            });
        });
    };
    TelegramBotHandler.prototype.handleStartMonitoringIP = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var ip, error_5;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        /** Handle start monitoring */
                        if (!args || args.length === 0) {
                            return [2 /*return*/, "❌ Usage: <code>/start_monitoring_ip [IP]</code>"];
                        }
                        ip = args[0];
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 4, , 5]);
                        // Validate IP
                        net.isIP(ip); // Returns 4 for IPv4, 6 for IPv6, 0 for invalid
                        this.monitor.monitoredIPs.add(ip);
                        return [4 /*yield*/, this.monitor.dbManager.addMonitoredIP(ip)];
                    case 2:
                        _a.sent();
                        this.monitor.saveConfig();
                        return [4 /*yield*/, this.monitor.dbManager.logCommand("start_monitoring_ip ".concat(ip), 'telegram', true)];
                    case 3:
                        _a.sent();
                        return [2 /*return*/, "\u2705 Started monitoring <code>".concat(ip, "</code>")];
                    case 4:
                        error_5 = _a.sent();
                        return [2 /*return*/, "\u274C Invalid IP: <code>".concat(ip, "</code>")];
                    case 5: return [2 /*return*/];
                }
            });
        });
    };
    TelegramBotHandler.prototype.handleStop = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var ips, _i, ips_1, ip;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        /** Handle stop */
                        if (this.monitor.monitoredIPs.size === 0) {
                            return [2 /*return*/, "⚠️ No IPs are being monitored"];
                        }
                        ips = Array.from(this.monitor.monitoredIPs);
                        this.monitor.monitoredIPs.clear();
                        _i = 0, ips_1 = ips;
                        _a.label = 1;
                    case 1:
                        if (!(_i < ips_1.length)) return [3 /*break*/, 4];
                        ip = ips_1[_i];
                        return [4 /*yield*/, this.monitor.dbManager.removeMonitoredIP(ip)];
                    case 2:
                        _a.sent();
                        _a.label = 3;
                    case 3:
                        _i++;
                        return [3 /*break*/, 1];
                    case 4:
                        this.monitor.saveConfig();
                        return [2 /*return*/, "\uD83D\uDED1 Stopped monitoring: ".concat(ips.join(', '))];
                }
            });
        });
    };
    TelegramBotHandler.prototype.handleHistory = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var history_1, response_1, error_6;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, , 3]);
                        return [4 /*yield*/, this.monitor.dbManager.getCommandHistory(20)];
                    case 1:
                        history_1 = _a.sent();
                        if (!history_1 || history_1.length === 0) {
                            return [2 /*return*/, "📝 No commands recorded"];
                        }
                        response_1 = "📝 <b>Command History</b>\n\n";
                        history_1.forEach(function (row, i) {
                            var status = row.success ? "✅" : "❌";
                            response_1 += "".concat(i + 1, ". ").concat(status, " <code>").concat(row.command, "</code>\n   ").concat(row.source, " | ").concat(row.timestamp, "\n\n");
                        });
                        return [2 /*return*/, response_1];
                    case 2:
                        error_6 = _a.sent();
                        return [2 /*return*/, "\u274C Error getting history: ".concat(error_6.message)];
                    case 3: return [2 /*return*/];
                }
            });
        });
    };
    TelegramBotHandler.prototype.handleAddIP = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var ip, error_7;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        /** Handle add IP */
                        if (!args || args.length === 0) {
                            return [2 /*return*/, "❌ Usage: <code>/add_ip [IP]</code>"];
                        }
                        ip = args[0];
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 5, , 6]);
                        if (!net.isIP(ip)) return [3 /*break*/, 3];
                        this.monitor.monitoredIPs.add(ip);
                        return [4 /*yield*/, this.monitor.dbManager.addMonitoredIP(ip)];
                    case 2:
                        _a.sent();
                        this.monitor.saveConfig();
                        return [2 /*return*/, "\u2705 Added <code>".concat(ip, "</code>")];
                    case 3: return [2 /*return*/, "\u274C Invalid IP: <code>".concat(ip, "</code>")];
                    case 4: return [3 /*break*/, 6];
                    case 5:
                        error_7 = _a.sent();
                        return [2 /*return*/, "\u274C Error: ".concat(error_7.message)];
                    case 6: return [2 /*return*/];
                }
            });
        });
    };
    TelegramBotHandler.prototype.handleRemoveIP = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var ip;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        /** Handle remove IP */
                        if (!args || args.length === 0) {
                            return [2 /*return*/, "❌ Usage: <code>/remove_ip [IP]</code>"];
                        }
                        ip = args[0];
                        if (!this.monitor.monitoredIPs.has(ip)) return [3 /*break*/, 2];
                        this.monitor.monitoredIPs.delete(ip);
                        return [4 /*yield*/, this.monitor.dbManager.removeMonitoredIP(ip)];
                    case 1:
                        _a.sent();
                        this.monitor.saveConfig();
                        return [2 /*return*/, "\u2705 Removed <code>".concat(ip, "</code>")];
                    case 2: return [2 /*return*/, "\u274C IP not in list: <code>".concat(ip, "</code>")];
                }
            });
        });
    };
    TelegramBotHandler.prototype.handleListIPs = function (args) {
        /** Handle list IPs */
        if (this.monitor.monitoredIPs.size === 0) {
            return "📋 No IPs are being monitored";
        }
        var response = "📋 <b>Monitored IPs</b>\n\n";
        Array.from(this.monitor.monitoredIPs).sort().forEach(function (ip) {
            response += "\u2022 <code>".concat(ip, "</code>\n");
        });
        return response;
    };
    TelegramBotHandler.prototype.handleClear = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var db_1, error_8;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, , 3]);
                        db_1 = new sqlite3.Database(DATABASE_FILE);
                        return [4 /*yield*/, new Promise(function (resolve, reject) {
                                db_1.run('DELETE FROM command_history', function (err) {
                                    if (err)
                                        reject(err);
                                    else
                                        resolve();
                                });
                            })];
                    case 1:
                        _a.sent();
                        db_1.close();
                        return [2 /*return*/, "✅ Command history cleared"];
                    case 2:
                        error_8 = _a.sent();
                        return [2 /*return*/, "\u274C Error clearing history: ".concat(error_8.message)];
                    case 3: return [2 /*return*/];
                }
            });
        });
    };
    TelegramBotHandler.prototype.handleTracertIP = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var target, result;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        /** Handle tracert */
                        if (!args || args.length === 0) {
                            return [2 /*return*/, "❌ Usage: <code>/tracert_ip [IP/domain]</code>"];
                        }
                        target = args[0];
                        return [4 /*yield*/, this.monitor.scanner.traceroute(target)];
                    case 1:
                        result = _a.sent();
                        return [2 /*return*/, result];
                }
            });
        });
    };
    TelegramBotHandler.prototype.handleTracerouteIP = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                /** Handle traceroute */
                return [2 /*return*/, this.handleTracertIP(args)];
            });
        });
    };
    TelegramBotHandler.prototype.handleAdvancedTraceroute = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var target, result;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        /** Handle advanced traceroute */
                        if (!args || args.length === 0) {
                            return [2 /*return*/, "❌ Usage: <code>/advanced_traceroute [IP/domain]</code>"];
                        }
                        target = args[0];
                        return [4 /*yield*/, this.sendTelegramMessage("\uD83D\uDEE3\uFE0F <b>Starting advanced traceroute to ".concat(target, "</b>..."))];
                    case 1:
                        _a.sent();
                        return [4 /*yield*/, this.monitor.scanner.traceroute(target)];
                    case 2:
                        result = _a.sent();
                        return [2 /*return*/, result];
                }
            });
        });
    };
    TelegramBotHandler.prototype.handleScanIP = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var ip, result, openPorts, response_2;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        /** Handle scan */
                        if (!args || args.length === 0) {
                            return [2 /*return*/, "❌ Usage: <code>/scan_ip [IP]</code>"];
                        }
                        ip = args[0];
                        return [4 /*yield*/, this.sendTelegramMessage("\uD83D\uDD0D Scanning <code>".concat(ip, "</code>..."))];
                    case 1:
                        _a.sent();
                        return [4 /*yield*/, this.monitor.scanner.portScan(ip)];
                    case 2:
                        result = _a.sent();
                        if (result.success) {
                            openPorts = result.openPorts || [];
                            response_2 = "\uD83D\uDD0D <b>Scan Results: ".concat(ip, "</b>\n\n");
                            response_2 += "Open Ports: ".concat(openPorts.length, "\n\n");
                            if (openPorts.length > 0) {
                                openPorts.slice(0, 10).forEach(function (p) {
                                    response_2 += "\u2022 Port ".concat(p.port, ": ").concat(p.service || 'unknown', "\n");
                                });
                                if (openPorts.length > 10) {
                                    response_2 += "\n... and ".concat(openPorts.length - 10, " more");
                                }
                            }
                            else {
                                response_2 += "🔒 No open ports found";
                            }
                            return [2 /*return*/, response_2];
                        }
                        return [2 /*return*/, "\u274C Scan error: ".concat(result.error || 'Unknown')];
                }
            });
        });
    };
    TelegramBotHandler.prototype.handleLocationIP = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var ip, result;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        /** Handle location */
                        if (!args || args.length === 0) {
                            return [2 /*return*/, "❌ Usage: <code>/location_ip [IP]</code>"];
                        }
                        ip = args[0];
                        return [4 /*yield*/, this.monitor.scanner.getIPLocation(ip)];
                    case 1:
                        result = _a.sent();
                        return [2 /*return*/, "\uD83C\uDF0D <b>Location: ".concat(ip, "</b>\n\n<code>").concat(result, "</code>")];
                }
            });
        });
    };
    TelegramBotHandler.prototype.handleAnalyzeIP = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var ip, response, location_1, locData, error_9, threats, ipThreats, error_10;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        /** Handle analyze */
                        if (!args || args.length === 0) {
                            return [2 /*return*/, "❌ Usage: <code>/analyze_ip [IP]</code>"];
                        }
                        ip = args[0];
                        response = "\uD83D\uDD0D <b>Analysis: ".concat(ip, "</b>\n\n");
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 3, , 4]);
                        return [4 /*yield*/, this.monitor.scanner.getIPLocation(ip)];
                    case 2:
                        location_1 = _a.sent();
                        locData = JSON.parse(location_1);
                        response += "\uD83D\uDCCD Location: ".concat(locData.city || 'N/A', ", ").concat(locData.country || 'N/A', "\n");
                        response += "\uD83C\uDFE2 ISP: ".concat(locData.isp || locData.org || 'N/A', "\n\n");
                        return [3 /*break*/, 4];
                    case 3:
                        error_9 = _a.sent();
                        return [3 /*break*/, 4];
                    case 4:
                        _a.trys.push([4, 6, , 7]);
                        return [4 /*yield*/, this.monitor.dbManager.getRecentThreats(5)];
                    case 5:
                        threats = _a.sent();
                        ipThreats = threats.filter(function (t) { return t.ip_address === ip; });
                        if (ipThreats.length > 0) {
                            response += "\uD83D\uDEA8 <b>Threats Found: ".concat(ipThreats.length, "</b>\n");
                            ipThreats.forEach(function (threat) {
                                response += "\u2022 ".concat(threat.threat_type, ": ").concat(threat.severity, "\n");
                            });
                        }
                        else {
                            response += "✅ No recent threats detected";
                        }
                        return [3 /*break*/, 7];
                    case 6:
                        error_10 = _a.sent();
                        response += "\u26A0\uFE0F Could not check threats: ".concat(error_10.message);
                        return [3 /*break*/, 7];
                    case 7: return [2 /*return*/, response];
                }
            });
        });
    };
    TelegramBotHandler.prototype.handleStatus = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var cpu, mem, network, response, error_11;
            var _a, _b;
            return __generator(this, function (_c) {
                switch (_c.label) {
                    case 0:
                        _c.trys.push([0, 4, , 5]);
                        return [4 /*yield*/, si.currentLoad()];
                    case 1:
                        cpu = _c.sent();
                        return [4 /*yield*/, si.mem()];
                    case 2:
                        mem = _c.sent();
                        return [4 /*yield*/, si.networkStats()];
                    case 3:
                        network = _c.sent();
                        response = "📊 <b>System Status</b>\n\n";
                        response += "\u2705 Bot: Online\n";
                        response += "\uD83D\uDD0D Monitored IPs: ".concat(this.monitor.monitoredIPs.size, "\n");
                        response += "\uD83D\uDCBB CPU: ".concat(cpu.currentload.toFixed(1), "%\n");
                        response += "\uD83E\uDDE0 Memory: ".concat(mem.used / mem.total * 100, "%\n");
                        response += "\uD83C\uDF10 Network: ".concat(((_a = network[0]) === null || _a === void 0 ? void 0 : _a.rx_sec) || 0, " RX/s, ").concat(((_b = network[0]) === null || _b === void 0 ? void 0 : _b.tx_sec) || 0, " TX/s\n");
                        return [2 /*return*/, response];
                    case 4:
                        error_11 = _c.sent();
                        return [2 /*return*/, "\u274C Error getting status: ".concat(error_11.message)];
                    case 5: return [2 /*return*/];
                }
            });
        });
    };
    TelegramBotHandler.prototype.handleCurl = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var url, response, result, preview, error_12;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        /** Handle curl */
                        if (!args || args.length === 0) {
                            return [2 /*return*/, "❌ Usage: <code>/curl [URL]</code>"];
                        }
                        url = args[args.length - 1];
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 3, , 4]);
                        return [4 /*yield*/, axios.get(url, { timeout: 10000 })];
                    case 2:
                        response = _a.sent();
                        result = "\uD83D\uDCE1 <b>CURL Response</b>\n\n";
                        result += "Status: ".concat(response.status, "\n");
                        result += "Size: ".concat(response.data.length, " bytes\n\n");
                        preview = response.data.toString().substring(0, 500);
                        result += "<code>".concat(preview, "</code>");
                        if (response.data.length > 500) {
                            result += "...";
                        }
                        return [2 /*return*/, result];
                    case 3:
                        error_12 = _a.sent();
                        return [2 /*return*/, "\u274C Error: ".concat(error_12.message)];
                    case 4: return [2 /*return*/];
                }
            });
        });
    };
    TelegramBotHandler.prototype.handleWhois = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var domain, result, error_13;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        /** Handle whois */
                        if (!args || args.length === 0) {
                            return [2 /*return*/, "❌ Usage: <code>/whois [domain]</code>"];
                        }
                        domain = args[0];
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 3, , 4]);
                        return [4 /*yield*/, this.monitor.scanner.whoisLookup(domain)];
                    case 2:
                        result = _a.sent();
                        return [2 /*return*/, "\uD83D\uDD0D <b>WHOIS: ".concat(domain, "</b>\n\n<code>").concat(result.substring(0, 1000), "</code>")];
                    case 3:
                        error_13 = _a.sent();
                        return [2 /*return*/, "\u274C WHOIS lookup failed: ".concat(error_13.message)];
                    case 4: return [2 /*return*/];
                }
            });
        });
    };
    TelegramBotHandler.prototype.handleDNSLookup = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var domain, addresses, error_14;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        /** Handle DNS lookup */
                        if (!args || args.length === 0) {
                            return [2 /*return*/, "❌ Usage: <code>/dns_lookup [domain]</code>"];
                        }
                        domain = args[0];
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 3, , 4]);
                        return [4 /*yield*/, dns.promises.resolve4(domain)];
                    case 2:
                        addresses = _a.sent();
                        return [2 /*return*/, "\uD83C\uDF10 <b>DNS Lookup</b>\n\n".concat(domain, " \u2192 <code>").concat(addresses[0], "</code>")];
                    case 3:
                        error_14 = _a.sent();
                        return [2 /*return*/, "\u274C DNS lookup failed: ".concat(error_14.message)];
                    case 4: return [2 /*return*/];
                }
            });
        });
    };
    TelegramBotHandler.prototype.handleNetworkInfo = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var hostname, interfaces, response_3;
            return __generator(this, function (_a) {
                /** Handle network info */
                try {
                    hostname = os.hostname();
                    interfaces = os.networkInterfaces();
                    response_3 = "🌐 <b>Network Information</b>\n\n";
                    response_3 += "Hostname: <code>".concat(hostname, "</code>\n\n");
                    response_3 += "<b>Network Interfaces:</b>\n";
                    Object.entries(interfaces).slice(0, 5).forEach(function (_a) {
                        var iface = _a[0], addresses = _a[1];
                        response_3 += "\n".concat(iface, ":\n");
                        addresses.slice(0, 2).forEach(function (addr) {
                            response_3 += "  ".concat(addr.address, " (").concat(addr.family, ")\n");
                        });
                    });
                    return [2 /*return*/, response_3];
                }
                catch (error) {
                    return [2 /*return*/, "\u274C Error: ".concat(error.message)];
                }
                return [2 /*return*/];
            });
        });
    };
    TelegramBotHandler.prototype.handleSystemInfo = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var cpu, mem, disk, osInfo, response, _a, _b, error_15;
            var _c;
            return __generator(this, function (_d) {
                switch (_d.label) {
                    case 0:
                        _d.trys.push([0, 6, , 7]);
                        return [4 /*yield*/, si.cpu()];
                    case 1:
                        cpu = _d.sent();
                        return [4 /*yield*/, si.mem()];
                    case 2:
                        mem = _d.sent();
                        return [4 /*yield*/, si.fsSize()];
                    case 3:
                        disk = _d.sent();
                        return [4 /*yield*/, si.osInfo()];
                    case 4:
                        osInfo = _d.sent();
                        response = "💻 <b>System Information</b>\n\n";
                        response += "OS: ".concat(osInfo.distro, " ").concat(osInfo.release, "\n");
                        response += "CPU: ".concat(cpu.manufacturer, " ").concat(cpu.brand, " (").concat(cpu.cores, " cores)\n");
                        _a = response;
                        _b = "CPU Usage: ".concat;
                        return [4 /*yield*/, si.currentLoad()];
                    case 5:
                        response = _a + _b.apply("CPU Usage: ", [(_d.sent()).currentload, "%\n"]);
                        response += "Memory: ".concat((mem.used / mem.total * 100).toFixed(1), "%\n");
                        response += "Disk: ".concat(((_c = disk[0]) === null || _c === void 0 ? void 0 : _c.use) || 0, "%\n");
                        response += "Uptime: ".concat(Math.floor(os.uptime() / 3600), "h ").concat(Math.floor((os.uptime() % 3600) / 60), "m\n");
                        return [2 /*return*/, response];
                    case 6:
                        error_15 = _d.sent();
                        return [2 /*return*/, "\u274C Error: ".concat(error_15.message)];
                    case 7: return [2 /*return*/];
                }
            });
        });
    };
    TelegramBotHandler.prototype.handleThreatSummary = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var threats, response_4, error_16;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, , 3]);
                        return [4 /*yield*/, this.monitor.dbManager.getRecentThreats(10)];
                    case 1:
                        threats = _a.sent();
                        if (!threats || threats.length === 0) {
                            return [2 /*return*/, "✅ No recent threats detected"];
                        }
                        response_4 = "🚨 <b>Recent Threats</b>\n\n";
                        threats.forEach(function (threat) {
                            response_4 += "\u2022 <code>".concat(threat.ip_address, "</code>\n");
                            response_4 += "  Type: ".concat(threat.threat_type, " | Severity: ").concat(threat.severity, "\n");
                            response_4 += "  Time: ".concat(threat.timestamp, "\n\n");
                        });
                        return [2 /*return*/, response_4];
                    case 2:
                        error_16 = _a.sent();
                        return [2 /*return*/, "\u274C Error: ".concat(error_16.message)];
                    case 3: return [2 /*return*/];
                }
            });
        });
    };
    TelegramBotHandler.prototype.handleGenerateReport = function (args) {
        return __awaiter(this, void 0, void 0, function () {
            var threats, history_2, report, filename, filepath, response, error_17;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 3, , 4]);
                        return [4 /*yield*/, this.monitor.dbManager.getRecentThreats(50)];
                    case 1:
                        threats = _a.sent();
                        return [4 /*yield*/, this.monitor.dbManager.getCommandHistory(100)];
                    case 2:
                        history_2 = _a.sent();
                        report = {
                            generated_at: new Date().toISOString(),
                            monitored_ips: this.monitor.monitoredIPs.size,
                            total_threats: threats.length,
                            high_severity: threats.filter(function (t) { return t.severity === 'high'; }).length,
                            medium_severity: threats.filter(function (t) { return t.severity === 'medium'; }).length,
                            low_severity: threats.filter(function (t) { return t.severity === 'low'; }).length,
                            commands_executed: history_2.length
                        };
                        filename = "report_".concat(Date.now(), ".json");
                        if (!fs.existsSync(REPORT_DIR)) {
                            fs.mkdirSync(REPORT_DIR, { recursive: true });
                        }
                        filepath = path.join(REPORT_DIR, filename);
                        fs.writeFileSync(filepath, JSON.stringify(report, null, 2));
                        response = "📊 <b>Security Report</b>\n\n";
                        response += "Monitored IPs: ".concat(report.monitored_ips, "\n");
                        response += "Total Threats: ".concat(report.total_threats, "\n");
                        response += "High Severity: ".concat(report.high_severity, "\n");
                        response += "Medium Severity: ".concat(report.medium_severity, "\n");
                        response += "Low Severity: ".concat(report.low_severity, "\n");
                        response += "\n\u2705 Report saved: <code>".concat(filename, "</code>");
                        return [2 /*return*/, response];
                    case 3:
                        error_17 = _a.sent();
                        return [2 /*return*/, "\u274C Error generating report: ".concat(error_17.message)];
                    case 4: return [2 /*return*/];
                }
            });
        });
    };
    TelegramBotHandler.prototype.processTelegramCommands = function () {
        return __awaiter(this, void 0, void 0, function () {
            var url, params, response, _i, _a, update, error_18;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        /** Process incoming Telegram commands */
                        if (!this.monitor.telegramToken || !axios) {
                            return [2 /*return*/];
                        }
                        _b.label = 1;
                    case 1:
                        _b.trys.push([1, 7, , 8]);
                        url = "https://api.telegram.org/bot".concat(this.monitor.telegramToken, "/getUpdates");
                        params = {
                            offset: this.lastUpdateId + 1,
                            timeout: 10
                        };
                        return [4 /*yield*/, axios.get(url, { params: params, timeout: 15000 })];
                    case 2:
                        response = _b.sent();
                        if (!(response.status === 200 && response.data.ok && response.data.result)) return [3 /*break*/, 6];
                        _i = 0, _a = response.data.result;
                        _b.label = 3;
                    case 3:
                        if (!(_i < _a.length)) return [3 /*break*/, 6];
                        update = _a[_i];
                        this.lastUpdateId = update.update_id;
                        if (!(update.message && update.message.text)) return [3 /*break*/, 5];
                        return [4 /*yield*/, this.processMessage(update.message)];
                    case 4:
                        _b.sent();
                        _b.label = 5;
                    case 5:
                        _i++;
                        return [3 /*break*/, 3];
                    case 6: return [3 /*break*/, 8];
                    case 7:
                        error_18 = _b.sent();
                        console.error("Telegram error: ".concat(error_18.message));
                        return [3 /*break*/, 8];
                    case 8: return [2 /*return*/];
                }
            });
        });
    };
    TelegramBotHandler.prototype.processMessage = function (message) {
        return __awaiter(this, void 0, void 0, function () {
            var text, chatId, error_19, parts, command, args, response, error_20;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        text = message.text;
                        chatId = message.chat.id.toString();
                        if (!this.monitor.telegramChatId) {
                            this.monitor.telegramChatId = chatId;
                            this.monitor.saveConfig();
                        }
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 3, , 4]);
                        return [4 /*yield*/, this.monitor.dbManager.logCommand(text, 'telegram', true)];
                    case 2:
                        _a.sent();
                        return [3 /*break*/, 4];
                    case 3:
                        error_19 = _a.sent();
                        console.error("Error logging command: ".concat(error_19.message));
                        return [3 /*break*/, 4];
                    case 4:
                        parts = text.split(/\s+/);
                        command = parts[0];
                        args = parts.slice(1);
                        if (!this.commandHandlers[command]) return [3 /*break*/, 11];
                        _a.label = 5;
                    case 5:
                        _a.trys.push([5, 8, , 10]);
                        return [4 /*yield*/, this.commandHandlers[command](args)];
                    case 6:
                        response = _a.sent();
                        return [4 /*yield*/, this.sendTelegramMessage(response)];
                    case 7:
                        _a.sent();
                        return [3 /*break*/, 10];
                    case 8:
                        error_20 = _a.sent();
                        return [4 /*yield*/, this.sendTelegramMessage("\u274C Error: ".concat(error_20.message))];
                    case 9:
                        _a.sent();
                        return [3 /*break*/, 10];
                    case 10: return [3 /*break*/, 13];
                    case 11: return [4 /*yield*/, this.sendTelegramMessage("❌ Unknown command. Type /help")];
                    case 12:
                        _a.sent();
                        _a.label = 13;
                    case 13: return [2 /*return*/];
                }
            });
        });
    };
    return TelegramBotHandler;
}());
exports.TelegramBotHandler = TelegramBotHandler;
var CybersecurityMonitor = /** @class */ (function () {
    function CybersecurityMonitor() {
        this.monitoredIPs = new Set();
        this.monitoringActive = false;
        this.telegramToken = null;
        this.telegramChatId = null;
        this.dbManager = new DatabaseManager();
        this.scanner = new NetworkScanner();
        this.tracerouteTool = new TracerouteTool();
        this.setupLogging();
        this.loadConfig();
    }
    CybersecurityMonitor.prototype.setupLogging = function () {
        /** Setup logging */
        // Console logging is already enabled by default
        console.log('Logging initialized');
    };
    CybersecurityMonitor.prototype.loadConfig = function () {
        /** Load configuration */
        try {
            if (fs.existsSync(CONFIG_FILE)) {
                var config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
                this.telegramToken = config.telegram_token || null;
                this.telegramChatId = config.telegram_chat_id || null;
                this.monitoredIPs = new Set(config.monitored_ips || []);
            }
        }
        catch (error) {
            console.error("Config load error: ".concat(error.message));
        }
    };
    CybersecurityMonitor.prototype.saveConfig = function () {
        /** Save configuration */
        try {
            var config = {
                telegram_token: this.telegramToken,
                telegram_chat_id: this.telegramChatId,
                monitored_ips: Array.from(this.monitoredIPs)
            };
            fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 4));
        }
        catch (error) {
            console.error("Config save error: ".concat(error.message));
        }
    };
    CybersecurityMonitor.prototype.loadMonitoredIPsFromDB = function () {
        return __awaiter(this, void 0, void 0, function () {
            var ips, error_21;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, , 3]);
                        return [4 /*yield*/, this.dbManager.getMonitoredIPs()];
                    case 1:
                        ips = _a.sent();
                        this.monitoredIPs = new Set(ips);
                        return [3 /*break*/, 3];
                    case 2:
                        error_21 = _a.sent();
                        console.error("Error loading IPs from DB: ".concat(error_21.message));
                        return [3 /*break*/, 3];
                    case 3: return [2 /*return*/];
                }
            });
        });
    };
    return CybersecurityMonitor;
}());
exports.CybersecurityMonitor = CybersecurityMonitor;
function printBanner() {
    /** Print banner */
    var banner = "\n    \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n    \u2551                                                       \u2551\n    \u2551          \uD83D\uDEE1\uFE0F  ACCURATE ONLINE OS DEMO \uD83D\uDEE1\uFE0F               \u2551\n    \u2551                                                       \u2551\n    \u2551                                                       \u2551\n    \u2551                                                       \u2551\n    \u2551                                                       \u2551\n    \u2551 Community:https://github.com/Accurate-Cyber-Defense   \u2551\n    \u2551              Telegram Bot: ACTIVE                     \u2551\n    \u2551              Database: Ready                          \u2551\n    \u2551                                                       \u2551\n    \u2551                                                       \u2551\n    \u2551                                                       \u2551\n    \u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D\n    ";
    console.log(banner);
}
function setupTelegram() {
    return __awaiter(this, void 0, void 0, function () {
        var rl;
        return __generator(this, function (_a) {
            /** Setup Telegram configuration */
            console.log("\n🔧 Telegram Bot Setup");
            console.log("=".repeat(50));
            console.log("\nTo use Telegram commands:");
            console.log("1. Create a bot with @BotFather on Telegram");
            console.log("2. Get your bot token");
            console.log("3. Start chat with your bot and send /start");
            console.log("4. Get your chat ID\n");
            rl = readline.createInterface({
                input: process.stdin,
                output: process.stdout
            });
            return [2 /*return*/, new Promise(function (resolve) {
                    rl.question("Enter Telegram bot token (or press Enter to skip): ", function (token) {
                        token = token.trim();
                        if (!token) {
                            rl.close();
                            resolve([null, null]);
                            return;
                        }
                        rl.question("Enter your chat ID: ", function (chatId) {
                            rl.close();
                            resolve([token, chatId.trim()]);
                        });
                    });
                })];
        });
    });
}
function main() {
    return __awaiter(this, void 0, void 0, function () {
        var monitor, telegramHandler, _a, token, chatId, telegramProcessor, testMsg, rl;
        var _this = this;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    monitor = new CybersecurityMonitor();
                    telegramHandler = new TelegramBotHandler(monitor);
                    printBanner();
                    // Load monitored IPs from database
                    return [4 /*yield*/, monitor.loadMonitoredIPsFromDB()];
                case 1:
                    // Load monitored IPs from database
                    _b.sent();
                    if (!!monitor.telegramToken) return [3 /*break*/, 3];
                    return [4 /*yield*/, setupTelegram()];
                case 2:
                    _a = _b.sent(), token = _a[0], chatId = _a[1];
                    if (token && chatId) {
                        monitor.telegramToken = token;
                        monitor.telegramChatId = chatId;
                        monitor.saveConfig();
                        console.log("✅ Telegram configured!");
                    }
                    else {
                        console.log("⚠️ Telegram features disabled");
                    }
                    _b.label = 3;
                case 3:
                    telegramProcessor = function () { return __awaiter(_this, void 0, void 0, function () {
                        var error_22;
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    if (!true) return [3 /*break*/, 7];
                                    _a.label = 1;
                                case 1:
                                    _a.trys.push([1, 4, , 6]);
                                    return [4 /*yield*/, telegramHandler.processTelegramCommands()];
                                case 2:
                                    _a.sent();
                                    return [4 /*yield*/, new Promise(function (resolve) { return setTimeout(resolve, 2000); })];
                                case 3:
                                    _a.sent();
                                    return [3 /*break*/, 6];
                                case 4:
                                    error_22 = _a.sent();
                                    console.error("Telegram error: ".concat(error_22.message));
                                    return [4 /*yield*/, new Promise(function (resolve) { return setTimeout(resolve, 10000); })];
                                case 5:
                                    _a.sent();
                                    return [3 /*break*/, 6];
                                case 6: return [3 /*break*/, 0];
                                case 7: return [2 /*return*/];
                            }
                        });
                    }); };
                    if (!(monitor.telegramToken && monitor.telegramChatId)) return [3 /*break*/, 5];
                    console.log("✅ Telegram bot ACTIVE");
                    console.log("📱 Send /start to your bot on Telegram");
                    // Start telegram processor in background
                    setImmediate(function () {
                        telegramProcessor().catch(function (error) {
                            console.error("Telegram processor error: ".concat(error.message));
                        });
                    });
                    testMsg = "🔗 <b>Accurate Online OS v2 - Connected!</b>\n\n✅ Bot is online\n🚀 Type /help for commands\n🛣️ Enhanced traceroute available!";
                    return [4 /*yield*/, telegramHandler.sendTelegramMessage(testMsg)];
                case 4:
                    _b.sent();
                    _b.label = 5;
                case 5:
                    console.log("\n💻 Local terminal commands available");
                    console.log("📋 Type 'help' for command list\n");
                    rl = readline.createInterface({
                        input: process.stdin,
                        output: process.stdout,
                        prompt: 'accurateOS> '
                    });
                    rl.prompt();
                    rl.on('line', function (line) { return __awaiter(_this, void 0, void 0, function () {
                        var command, error_23, parts, cmd, args, result, result, result, result, openPorts, result, ip_1, location_2, locData, error_24, threats, ipThreats, error_25, result, error_26, addresses, error_27, ip, ip, ip, ips, _i, ips_2, ip, hostname, interfaces, cpu, mem, osInfo, _a, _b, _c, error_28, cpu, mem, error_29, history_3, error_30, threats, error_31, threats, history_4, report, filename, filepath, error_32, _d, token, chatId;
                        return __generator(this, function (_e) {
                            switch (_e.label) {
                                case 0:
                                    command = line.trim();
                                    if (!command) {
                                        rl.prompt();
                                        return [2 /*return*/];
                                    }
                                    _e.label = 1;
                                case 1:
                                    _e.trys.push([1, 3, , 4]);
                                    return [4 /*yield*/, monitor.dbManager.logCommand(command, 'local', true)];
                                case 2:
                                    _e.sent();
                                    return [3 /*break*/, 4];
                                case 3:
                                    error_23 = _e.sent();
                                    console.error("Error logging command: ".concat(error_23.message));
                                    return [3 /*break*/, 4];
                                case 4:
                                    parts = command.split(/\s+/);
                                    cmd = parts[0].toLowerCase();
                                    args = parts.slice(1);
                                    if (!(cmd === 'exit')) return [3 /*break*/, 5];
                                    console.log("👋 Exiting...");
                                    rl.close();
                                    process.exit(0);
                                    return [3 /*break*/, 88];
                                case 5:
                                    if (!(cmd === 'help')) return [3 /*break*/, 6];
                                    console.log("\nLocal Commands:\n  ping [ip]              - Ping IP address\n  tracert [ip]           - Traceroute (Windows)\n  traceroute [ip]        - Traceroute (Linux/Mac)\n  advanced_traceroute [ip] - Enhanced traceroute\n  scan [ip]              - Port scan\n  location [ip]          - Get IP location\n  analyze [ip]           - Analyze IP\n  whois [domain]         - WHOIS lookup\n  dns [domain]           - DNS lookup\n  \n  start_monitoring [ip]  - Start monitoring IP\n  add [ip]               - Add IP to monitoring\n  remove [ip]            - Remove IP\n  list                   - List monitored IPs\n  stop                   - Stop monitoring\n  \n  network_info           - Network information\n  system_info            - System information\n  status                 - System status\n  history                - Command history\n  threats                - Threat summary\n  report                 - Generate report\n  \n  config                 - Configure Telegram\n  clear                  - Clear screen\n  exit                   - Exit program\n\nAll commands also available via Telegram!\n            ");
                                    return [3 /*break*/, 88];
                                case 6:
                                    if (!(cmd === 'ping' && args.length > 0)) return [3 /*break*/, 8];
                                    return [4 /*yield*/, monitor.scanner.pingIP(args[0])];
                                case 7:
                                    result = _e.sent();
                                    console.log(result);
                                    return [3 /*break*/, 88];
                                case 8:
                                    if (!((cmd === 'tracert' || cmd === 'traceroute') && args.length > 0)) return [3 /*break*/, 10];
                                    console.log("Traceroute to ".concat(args[0], "..."));
                                    return [4 /*yield*/, monitor.scanner.traceroute(args[0])];
                                case 9:
                                    result = _e.sent();
                                    console.log(result);
                                    return [3 /*break*/, 88];
                                case 10:
                                    if (!(cmd === 'advanced_traceroute' && args.length > 0)) return [3 /*break*/, 12];
                                    console.log("\uD83D\uDE80 Advanced traceroute to ".concat(args[0], "..."));
                                    return [4 /*yield*/, monitor.tracerouteTool.interactiveTraceroute(args[0])];
                                case 11:
                                    result = _e.sent();
                                    console.log(result);
                                    return [3 /*break*/, 88];
                                case 12:
                                    if (!(cmd === 'scan' && args.length > 0)) return [3 /*break*/, 14];
                                    console.log("Scanning ".concat(args[0], "..."));
                                    return [4 /*yield*/, monitor.scanner.portScan(args[0])];
                                case 13:
                                    result = _e.sent();
                                    if (result.success) {
                                        console.log("\n\uD83D\uDCCA Scan Results for ".concat(args[0], ":"));
                                        openPorts = result.openPorts || [];
                                        console.log("Open Ports: ".concat(openPorts.length, "\n"));
                                        openPorts.forEach(function (p) {
                                            console.log("  Port ".concat(p.port, ": ").concat(p.service || 'unknown'));
                                        });
                                    }
                                    else {
                                        console.log("\u274C Error: ".concat(result.error || 'Unknown'));
                                    }
                                    return [3 /*break*/, 88];
                                case 14:
                                    if (!(cmd === 'location' && args.length > 0)) return [3 /*break*/, 16];
                                    return [4 /*yield*/, monitor.scanner.getIPLocation(args[0])];
                                case 15:
                                    result = _e.sent();
                                    console.log(result);
                                    return [3 /*break*/, 88];
                                case 16:
                                    if (!(cmd === 'analyze' && args.length > 0)) return [3 /*break*/, 24];
                                    ip_1 = args[0];
                                    console.log("\n\uD83D\uDD0D Analyzing ".concat(ip_1, "...\n"));
                                    _e.label = 17;
                                case 17:
                                    _e.trys.push([17, 19, , 20]);
                                    return [4 /*yield*/, monitor.scanner.getIPLocation(ip_1)];
                                case 18:
                                    location_2 = _e.sent();
                                    locData = JSON.parse(location_2);
                                    console.log("\uD83D\uDCCD Location: ".concat(locData.city || 'N/A', ", ").concat(locData.country || 'N/A'));
                                    console.log("\uD83C\uDFE2 ISP: ".concat(locData.isp || locData.org || 'N/A', "\n"));
                                    return [3 /*break*/, 20];
                                case 19:
                                    error_24 = _e.sent();
                                    return [3 /*break*/, 20];
                                case 20:
                                    _e.trys.push([20, 22, , 23]);
                                    return [4 /*yield*/, monitor.dbManager.getRecentThreats(10)];
                                case 21:
                                    threats = _e.sent();
                                    ipThreats = threats.filter(function (t) { return t.ip_address === ip_1; });
                                    if (ipThreats.length > 0) {
                                        console.log("\uD83D\uDEA8 Threats Found: ".concat(ipThreats.length));
                                        ipThreats.forEach(function (threat) {
                                            console.log("  \u2022 ".concat(threat.threat_type, ": ").concat(threat.severity));
                                        });
                                    }
                                    else {
                                        console.log("✅ No recent threats detected");
                                    }
                                    return [3 /*break*/, 23];
                                case 22:
                                    error_25 = _e.sent();
                                    console.log("\u26A0\uFE0F Could not check threats: ".concat(error_25.message));
                                    return [3 /*break*/, 23];
                                case 23: return [3 /*break*/, 88];
                                case 24:
                                    if (!(cmd === 'whois' && args.length > 0)) return [3 /*break*/, 29];
                                    _e.label = 25;
                                case 25:
                                    _e.trys.push([25, 27, , 28]);
                                    return [4 /*yield*/, monitor.scanner.whoisLookup(args[0])];
                                case 26:
                                    result = _e.sent();
                                    console.log(result);
                                    return [3 /*break*/, 28];
                                case 27:
                                    error_26 = _e.sent();
                                    console.log("\u274C WHOIS lookup failed: ".concat(error_26.message));
                                    return [3 /*break*/, 28];
                                case 28: return [3 /*break*/, 88];
                                case 29:
                                    if (!(cmd === 'dns' && args.length > 0)) return [3 /*break*/, 34];
                                    _e.label = 30;
                                case 30:
                                    _e.trys.push([30, 32, , 33]);
                                    return [4 /*yield*/, dns.promises.resolve4(args[0])];
                                case 31:
                                    addresses = _e.sent();
                                    console.log("\uD83C\uDF10 ".concat(args[0], " \u2192 ").concat(addresses[0]));
                                    return [3 /*break*/, 33];
                                case 32:
                                    error_27 = _e.sent();
                                    console.log("\u274C DNS lookup failed: ".concat(error_27.message));
                                    return [3 /*break*/, 33];
                                case 33: return [3 /*break*/, 88];
                                case 34:
                                    if (!(cmd === 'start_monitoring' && args.length > 0)) return [3 /*break*/, 38];
                                    ip = args[0];
                                    if (!net.isIP(ip)) return [3 /*break*/, 36];
                                    monitor.monitoredIPs.add(ip);
                                    return [4 /*yield*/, monitor.dbManager.addMonitoredIP(ip)];
                                case 35:
                                    _e.sent();
                                    monitor.saveConfig();
                                    console.log("\u2705 Started monitoring ".concat(ip));
                                    return [3 /*break*/, 37];
                                case 36:
                                    console.log("\u274C Invalid IP: ".concat(ip));
                                    _e.label = 37;
                                case 37: return [3 /*break*/, 88];
                                case 38:
                                    if (!(cmd === 'add' && args.length > 0)) return [3 /*break*/, 42];
                                    ip = args[0];
                                    if (!net.isIP(ip)) return [3 /*break*/, 40];
                                    monitor.monitoredIPs.add(ip);
                                    return [4 /*yield*/, monitor.dbManager.addMonitoredIP(ip)];
                                case 39:
                                    _e.sent();
                                    monitor.saveConfig();
                                    console.log("\u2705 Added ".concat(ip));
                                    return [3 /*break*/, 41];
                                case 40:
                                    console.log("\u274C Invalid IP: ".concat(ip));
                                    _e.label = 41;
                                case 41: return [3 /*break*/, 88];
                                case 42:
                                    if (!(cmd === 'remove' && args.length > 0)) return [3 /*break*/, 46];
                                    ip = args[0];
                                    if (!monitor.monitoredIPs.has(ip)) return [3 /*break*/, 44];
                                    monitor.monitoredIPs.delete(ip);
                                    return [4 /*yield*/, monitor.dbManager.removeMonitoredIP(ip)];
                                case 43:
                                    _e.sent();
                                    monitor.saveConfig();
                                    console.log("\u2705 Removed ".concat(ip));
                                    return [3 /*break*/, 45];
                                case 44:
                                    console.log("\u274C IP not in list: ".concat(ip));
                                    _e.label = 45;
                                case 45: return [3 /*break*/, 88];
                                case 46:
                                    if (!(cmd === 'list')) return [3 /*break*/, 47];
                                    if (monitor.monitoredIPs.size > 0) {
                                        console.log("\n📋 Monitored IPs:");
                                        Array.from(monitor.monitoredIPs).sort().forEach(function (ip) {
                                            console.log("  \u2022 ".concat(ip));
                                        });
                                    }
                                    else {
                                        console.log("📋 No IPs are being monitored");
                                    }
                                    return [3 /*break*/, 88];
                                case 47:
                                    if (!(cmd === 'stop')) return [3 /*break*/, 54];
                                    if (!(monitor.monitoredIPs.size > 0)) return [3 /*break*/, 52];
                                    ips = Array.from(monitor.monitoredIPs);
                                    monitor.monitoredIPs.clear();
                                    _i = 0, ips_2 = ips;
                                    _e.label = 48;
                                case 48:
                                    if (!(_i < ips_2.length)) return [3 /*break*/, 51];
                                    ip = ips_2[_i];
                                    return [4 /*yield*/, monitor.dbManager.removeMonitoredIP(ip)];
                                case 49:
                                    _e.sent();
                                    _e.label = 50;
                                case 50:
                                    _i++;
                                    return [3 /*break*/, 48];
                                case 51:
                                    monitor.saveConfig();
                                    console.log("\uD83D\uDED1 Stopped monitoring: ".concat(ips.join(', ')));
                                    return [3 /*break*/, 53];
                                case 52:
                                    console.log("⚠️ No IPs are being monitored");
                                    _e.label = 53;
                                case 53: return [3 /*break*/, 88];
                                case 54:
                                    if (!(cmd === 'network_info')) return [3 /*break*/, 55];
                                    hostname = os.hostname();
                                    interfaces = os.networkInterfaces();
                                    console.log("\n\uD83C\uDF10 Network Information:");
                                    console.log("  Hostname: ".concat(hostname));
                                    console.log("  Interfaces: ".concat(Object.keys(interfaces).length));
                                    Object.entries(interfaces).slice(0, 3).forEach(function (_a) {
                                        var iface = _a[0], addresses = _a[1];
                                        console.log("  ".concat(iface, ":"));
                                        addresses.slice(0, 2).forEach(function (addr) {
                                            console.log("    ".concat(addr.address, " (").concat(addr.family, ")"));
                                        });
                                    });
                                    return [3 /*break*/, 88];
                                case 55:
                                    if (!(cmd === 'system_info')) return [3 /*break*/, 63];
                                    _e.label = 56;
                                case 56:
                                    _e.trys.push([56, 61, , 62]);
                                    return [4 /*yield*/, si.cpu()];
                                case 57:
                                    cpu = _e.sent();
                                    return [4 /*yield*/, si.mem()];
                                case 58:
                                    mem = _e.sent();
                                    return [4 /*yield*/, si.osInfo()];
                                case 59:
                                    osInfo = _e.sent();
                                    console.log("\n\uD83D\uDCBB System Information:");
                                    console.log("  OS: ".concat(osInfo.distro, " ").concat(osInfo.release));
                                    console.log("  CPU: ".concat(cpu.manufacturer, " ").concat(cpu.brand, " (").concat(cpu.cores, " cores)"));
                                    _b = (_a = console).log;
                                    _c = "  CPU Usage: ".concat;
                                    return [4 /*yield*/, si.currentLoad()];
                                case 60:
                                    _b.apply(_a, [_c.apply("  CPU Usage: ", [(_e.sent()).currentload, "%"])]);
                                    console.log("  Memory: ".concat((mem.used / mem.total * 100).toFixed(1), "%"));
                                    console.log("  Uptime: ".concat(Math.floor(os.uptime() / 3600), "h ").concat(Math.floor((os.uptime() % 3600) / 60), "m"));
                                    return [3 /*break*/, 62];
                                case 61:
                                    error_28 = _e.sent();
                                    console.log("\u274C Error: ".concat(error_28.message));
                                    return [3 /*break*/, 62];
                                case 62: return [3 /*break*/, 88];
                                case 63:
                                    if (!(cmd === 'status')) return [3 /*break*/, 69];
                                    _e.label = 64;
                                case 64:
                                    _e.trys.push([64, 67, , 68]);
                                    return [4 /*yield*/, si.currentLoad()];
                                case 65:
                                    cpu = _e.sent();
                                    return [4 /*yield*/, si.mem()];
                                case 66:
                                    mem = _e.sent();
                                    console.log("\n\uD83D\uDCCA System Status:");
                                    console.log("  Bot: ".concat(monitor.telegramToken ? 'Online' : 'Offline'));
                                    console.log("  Monitored IPs: ".concat(monitor.monitoredIPs.size));
                                    console.log("  CPU: ".concat(cpu.currentload.toFixed(1), "%"));
                                    console.log("  Memory: ".concat((mem.used / mem.total * 100).toFixed(1), "%"));
                                    console.log("  Uptime: ".concat(Math.floor(os.uptime() / 3600), "h ").concat(Math.floor((os.uptime() % 3600) / 60), "m"));
                                    return [3 /*break*/, 68];
                                case 67:
                                    error_29 = _e.sent();
                                    console.log("\u274C Error: ".concat(error_29.message));
                                    return [3 /*break*/, 68];
                                case 68: return [3 /*break*/, 88];
                                case 69:
                                    if (!(cmd === 'history')) return [3 /*break*/, 74];
                                    _e.label = 70;
                                case 70:
                                    _e.trys.push([70, 72, , 73]);
                                    return [4 /*yield*/, monitor.dbManager.getCommandHistory(20)];
                                case 71:
                                    history_3 = _e.sent();
                                    if (history_3 && history_3.length > 0) {
                                        console.log("\n📜 Command History:");
                                        history_3.forEach(function (row, i) {
                                            var status = row.success ? "✅" : "❌";
                                            console.log("  ".concat(i + 1, ". ").concat(status, " [").concat(row.source, "] ").concat(row.command, " | ").concat(row.timestamp));
                                        });
                                    }
                                    else {
                                        console.log("📜 No commands recorded");
                                    }
                                    return [3 /*break*/, 73];
                                case 72:
                                    error_30 = _e.sent();
                                    console.log("\u274C Error: ".concat(error_30.message));
                                    return [3 /*break*/, 73];
                                case 73: return [3 /*break*/, 88];
                                case 74:
                                    if (!(cmd === 'threats')) return [3 /*break*/, 79];
                                    _e.label = 75;
                                case 75:
                                    _e.trys.push([75, 77, , 78]);
                                    return [4 /*yield*/, monitor.dbManager.getRecentThreats(10)];
                                case 76:
                                    threats = _e.sent();
                                    if (threats && threats.length > 0) {
                                        console.log("\n🚨 Recent Threats:");
                                        threats.forEach(function (threat) {
                                            console.log("  \u2022 ".concat(threat.ip_address));
                                            console.log("    Type: ".concat(threat.threat_type, " | Severity: ").concat(threat.severity));
                                            console.log("    Time: ".concat(threat.timestamp, "\n"));
                                        });
                                    }
                                    else {
                                        console.log("✅ No recent threats detected");
                                    }
                                    return [3 /*break*/, 78];
                                case 77:
                                    error_31 = _e.sent();
                                    console.log("\u274C Error: ".concat(error_31.message));
                                    return [3 /*break*/, 78];
                                case 78: return [3 /*break*/, 88];
                                case 79:
                                    if (!(cmd === 'report')) return [3 /*break*/, 85];
                                    _e.label = 80;
                                case 80:
                                    _e.trys.push([80, 83, , 84]);
                                    return [4 /*yield*/, monitor.dbManager.getRecentThreats(50)];
                                case 81:
                                    threats = _e.sent();
                                    return [4 /*yield*/, monitor.dbManager.getCommandHistory(100)];
                                case 82:
                                    history_4 = _e.sent();
                                    report = {
                                        generated_at: new Date().toISOString(),
                                        monitored_ips: monitor.monitoredIPs.size,
                                        total_threats: threats.length,
                                        high_severity: threats.filter(function (t) { return t.severity === 'high'; }).length,
                                        medium_severity: threats.filter(function (t) { return t.severity === 'medium'; }).length,
                                        low_severity: threats.filter(function (t) { return t.severity === 'low'; }).length,
                                        commands_executed: history_4.length
                                    };
                                    filename = "report_".concat(Date.now(), ".json");
                                    if (!fs.existsSync(REPORT_DIR)) {
                                        fs.mkdirSync(REPORT_DIR, { recursive: true });
                                    }
                                    filepath = path.join(REPORT_DIR, filename);
                                    fs.writeFileSync(filepath, JSON.stringify(report, null, 2));
                                    console.log("\n\uD83D\uDCCA Security Report:");
                                    console.log("  Monitored IPs: ".concat(report.monitored_ips));
                                    console.log("  Total Threats: ".concat(report.total_threats));
                                    console.log("  High Severity: ".concat(report.high_severity));
                                    console.log("  Medium Severity: ".concat(report.medium_severity));
                                    console.log("  Low Severity: ".concat(report.low_severity));
                                    console.log("\n\u2705 Report saved: ".concat(filename));
                                    return [3 /*break*/, 84];
                                case 83:
                                    error_32 = _e.sent();
                                    console.log("\u274C Error: ".concat(error_32.message));
                                    return [3 /*break*/, 84];
                                case 84: return [3 /*break*/, 88];
                                case 85:
                                    if (!(cmd === 'config')) return [3 /*break*/, 87];
                                    return [4 /*yield*/, setupTelegram()];
                                case 86:
                                    _d = _e.sent(), token = _d[0], chatId = _d[1];
                                    if (token && chatId) {
                                        monitor.telegramToken = token;
                                        monitor.telegramChatId = chatId;
                                        monitor.saveConfig();
                                        console.log("✅ Telegram configured!");
                                    }
                                    return [3 /*break*/, 88];
                                case 87:
                                    if (cmd === 'clear') {
                                        console.clear();
                                        printBanner();
                                    }
                                    else {
                                        console.log("Unknown command. Type 'help' for available commands.");
                                    }
                                    _e.label = 88;
                                case 88:
                                    rl.prompt();
                                    return [2 /*return*/];
                            }
                        });
                    }); }).on('close', function () {
                        console.log("👋 Thank you for using Accurate Online OS Demo!");
                        process.exit(0);
                    });
                    return [2 /*return*/];
            }
        });
    });
}
// Handle application errors
process.on('uncaughtException', function (error) {
    console.error("\u274C Uncaught Exception: ".concat(error.message));
    console.error(error.stack);
});
process.on('unhandledRejection', function (reason, promise) {
    console.error("\u274C Unhandled Rejection at: ".concat(promise, ", reason: ").concat(reason));
});
// Run the application
if (require.main === module) {
    main().catch(function (error) {
        console.error("\u274C Application error: ".concat(error.message));
        console.error(error.stack);
        process.exit(1);
    });
}
