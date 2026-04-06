// ==PinePartner Plugin==
// @id trains-schedule
// @name Adif integration
// @permission HTTP
// ==/PinePartner Plugin==

const watches = require("watches");
const http = require("http");

function onWatchConnected(watch) {
    const trainsService = watch.getService("00070000-78fc-48fe-8e23-433b3a1942d0");
    const open = trainsService.getCharacteristic("00070001-78fc-48fe-8e23-433b3a1942d0");
    const schedule = trainsService.getCharacteristic("00070002-78fc-48fe-8e23-433b3a1942d0");

    open.addEventListener("notify", val => {
    });
}

watches.addEventListener("connected", onWatchConnected)
watches.all.forEach(onWatchConnected)

console.log("ready");
