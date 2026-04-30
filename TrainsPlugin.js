// ==PinePartner Plugin==
// @id trains-schedule
// @name Adif integration
// @permission HTTP
// @permission LOCATION
// ==/PinePartner Plugin==

const watches = require("watches");
const http = require("http");
const location = require("location");

const API_ENDPOINT = "https://pipe01.net/renfe";

const HOME_STATION = 50702;
const WORK_STATION = 51110;

let stations;
http.request("GET", `${API_ENDPOINT}/api/v1/stations`, v => stations = JSON.parse(v));

function onWatchConnected(watch) {
    const trainsService = watch.getService("00070000-78fc-48fe-8e23-433b3a1942d0");
    const open = trainsService.getCharacteristic("00070001-78fc-48fe-8e23-433b3a1942d0");
    const schedule = trainsService.getCharacteristic("00070002-78fc-48fe-8e23-433b3a1942d0");

    open.addEventListener("notify", () => {
        console.log("opened");

        try {
            const closest = getClosestStation();
            const destination = closest.Code == HOME_STATION ? stations[WORK_STATION] : stations[HOME_STATION];

            console.log("from", closest.Name, "to", destination.Name);

            const trains = fetchTrainData(closest.Code, destination.Code);
            const firstTrain = trains.find(t => new Date(t.Origin.Departure.RealTime).valueOf() > new Date().valueOf());

            const data = [1];
            const plannedTime = new Date(firstTrain.Origin.Departure.PlannedTime);
            const realTime = new Date(firstTrain.Origin.Departure.RealTime);
            const secondsLeft = Math.round((realTime.valueOf() - new Date().valueOf()) / 1000);
            const delaySeconds = Math.round((realTime.valueOf() - plannedTime.valueOf()) / 1000);

            data.push(secondsLeft & 0xFF, (secondsLeft >> 8) & 0xFF);
            data.push(delaySeconds & 0xFF, (delaySeconds >> 8) & 0xFF);

            writeString(data, closest.Name);
            writeString(data, destination.Name);

            schedule.write(new Uint8Array(data));
        } catch (e) {
            schedule.write(new Uint8Array([0]));
            console.error(e);
        }
    });
}

watches.addEventListener("connected", onWatchConnected)
watches.all.forEach(onWatchConnected)

function fetchTrainData(origin, destination) {
    const resp = http.request("GET", `${API_ENDPOINT}/api/v1/future/routes?origin=${origin}&destination=${destination}`)

    if (!resp) {
        return null;
    }

    const data = JSON.parse(resp);
    if (data.length == 0) {
        return null;
    }

    return data;
}

function getClosestStation() {
    let pos = location.getCurrent("lowPower", "coarse");
    // let pos = { latitude: 37.356527, longitude: -5.986342 }
    if (!pos) {
        console.error("failed to get position");
        return null;
    }

    if (!stations) return null;

    console.log("got location", pos.latitude, pos.longitude);

    let closest = null, closestDist = Infinity;

    for (let station of Object.values(stations)) {
        if (station.Code < 50000 || station.Code > 52000 || (station.TrafficType & 2) != 2)
            continue;

        let dist = haversineDistanceKM(pos.latitude, pos.longitude, station.Latitude, station.Longitude);

        if (!isNaN(dist) && dist < closestDist) {
            closest = station;
            closestDist = dist;
        }
    }

    return closest;
}

function writeString(arr, str) {
    str = str.normalize("NFD"); // Remove diacritics
    arr.push(str.length);
    [...str].forEach(v => arr.push(v.charCodeAt(0)));
}

function haversineDistanceKM(lat1Deg, lon1Deg, lat2Deg, lon2Deg) {
    function toRad(degree) {
        return degree * Math.PI / 180;
    }

    const lat1 = toRad(lat1Deg);
    const lon1 = toRad(lon1Deg);
    const lat2 = toRad(lat2Deg);
    const lon2 = toRad(lon2Deg);

    const { sin, cos, sqrt, atan2 } = Math;

    const R = 6371; // earth radius in km 
    const dLat = lat2 - lat1;
    const dLon = lon2 - lon1;
    const a = sin(dLat / 2) * sin(dLat / 2)
        + cos(lat1) * cos(lat2)
        * sin(dLon / 2) * sin(dLon / 2);
    const c = 2 * atan2(sqrt(a), sqrt(1 - a));
    const d = R * c;
    return d; // distance in km
}
