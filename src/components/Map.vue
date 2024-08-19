<template>
  <div class="container">
    <div class="content">
      <h2 class="title">Crime Alert</h2>
      <button v-if="!formVisible" class="btn btn-primary" @click="showForm">Report</button>
      <div v-if="formVisible" class="form-container">
        <h4 class="form-title">Report Your Experience</h4>
        <form @submit.prevent="submitForm">
          <div class="form-group">
            <label for="crimeType">Type of Crime:</label>
            <select v-model="crimeType" id="crimeType" class="form-control" required>
              <option value="" disabled>Select a crime</option>
              <option value="experienced">Experienced a crime</option>
              <option value="witnessed">Witnessed a crime</option>
            </select>
          </div>
          <div class="form-group">
            <label for="specificCrime">Specific Crime:</label>
            <select v-model="specificCrime" id="specificCrime" class="form-control" required>
              <option value="" disabled>Select specific crime</option>
              <option value="theft">Theft</option>
              <option value="assault">Assault</option>
              <option value="vandalism">Vandalism</option>
              <!-- Add more specific crimes as needed -->
            </select>
          </div>
          <button type="submit" class="btn btn-primary">Submit</button>
          <button type="button" class="btn btn-secondary" @click="cancelForm">Cancel</button>
        </form>
      </div>
      <div v-if="retryButtonVisible" class="ui-message">
        <p>Failed to fetch accurate location. <button class="btn btn-secondary" @click="retryFetchLocation">Retry</button></p>
      </div>
      <button v-if="currentLocation && !riskLevelFormVisible && !dangerZoneFormVisible" class="btn btn-danger" @click="enableRiskLevelForm">Set Danger Zone</button>
      <div v-if="riskLevelFormVisible" class="form-container">
        <h4 class="form-title">Select Risk Level</h4>
        <form @submit.prevent="confirmRiskLevel">
          <div class="form-group">
            <label for="riskLevel">Risk Level:</label>
            <select v-model="riskLevel" id="riskLevel" class="form-control" required>
              <option value="" disabled>Select risk level</option>
              <option value="high">High Risk</option>
              <option value="medium">Medium Risk</option>
              <option value="low">Low Risk</option>
            </select>
          </div>
          <button type="submit" class="btn btn-primary">Confirm</button>
          <button type="button" class="btn btn-secondary" @click="cancelRiskLevelForm">Cancel</button>
        </form>
      </div>
      <div v-if="dangerZoneFormVisible" class="form-container">
        <h4 class="form-title">Set Danger Zone</h4>
        <p>Click on the map to set a danger zone within 1000 meters of your location.</p>
        <button type="button" class="btn btn-primary" @click="confirmDangerZone">Confirm</button>
        <button type="button" class="btn btn-secondary" @click="cancelDangerZoneSetting">Cancel</button>
      </div>
      <div id="map" class="map"></div>
      <div v-if="locationDisplay" class="ui-message">
        <div v-html="locationDisplay"></div>
      </div>
      <div v-if="dangerZones.length > 0" class="danger-zones">
        <h4 class="danger-zones-title">Danger Zones</h4>
        <ul>
          <li v-for="(zone, index) in dangerZones" :key="index" class="danger-zone-item">
            Zone {{ index + 1 }} ({{ zone.latLng.lat.toFixed(5) }}, {{ zone.latLng.lng.toFixed(5) }}) - {{ zone.riskLevel }}
            <button class="btn btn-sm btn-danger" @click="removeDangerZone(index)">Remove</button>
          </li>
        </ul>
      </div>
    </div>
  </div>
</template>

<script>
import L from 'leaflet';
import axios from 'axios';
import 'leaflet/dist/leaflet.css';

export default {
  name: 'MapVue',
  data() {
    return {
      map: null,
      circle: null,
      locationDisplay: '',
      retryButtonVisible: false,
      dangerZones: [],
      currentLocation: null,
      formVisible: false,
      riskLevelFormVisible: false,
      dangerZoneFormVisible: false,
      crimeType: '',
      specificCrime: '',
      riskLevel: '',
      dangerZoneRadius: 700,
      isSettingDangerZone: false,
      areaName: ''
    };
  },
  mounted() {
    this.initMap();
  },
  methods: {
    initMap() {
      this.map = L.map('map').setView([51.505, -0.09], 13);

      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
      }).addTo(this.map);

      this.map.on('click', this.handleMapClick);
    },
    showForm() {
      this.formVisible = true;
    },
    cancelForm() {
      this.formVisible = false;
    },
    submitForm() {
      console.log('Crime Type:', this.crimeType);
      console.log('Specific Crime:', this.specificCrime);
      this.formVisible = false;
      this.fetchLocation();
    },
    fetchLocation() {
      console.log('Fetching location...');
      if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(
          this.showPosition,
          this.showError,
          {
            enableHighAccuracy: true,
            timeout: 10000,
            maximumAge: 0
          }
        );
      } else {
        this.locationDisplay = "Geolocation is not supported by this browser.";
      }
    },
    retryFetchLocation() {
      console.log('Retry button clicked');
      this.fetchLocation();
    },
    async showPosition(position) {
      const latitude = position.coords.latitude;
      const longitude = position.coords.longitude;
      const accuracy = position.coords.accuracy;

      console.log('Current Location:', latitude, longitude);
      console.log('Accuracy:', accuracy);

      this.currentLocation = [latitude, longitude];
      this.map.setView(this.currentLocation, 13);

      if (this.circle) {
        this.circle.setLatLng(this.currentLocation);
        this.circle.setRadius(accuracy > this.dangerZoneRadius ? this.dangerZoneRadius : accuracy);
      } else {
        this.circle = L.circle(this.currentLocation, {
          color: 'blue',
          fillColor: '#30f',
          fillOpacity: 0.2,
          radius: accuracy > this.dangerZoneRadius ? this.dangerZoneRadius : accuracy
        }).addTo(this.map);
      }

      // Reverse geocode to get area name
      try {
        const response = await axios.get(`https://nominatim.openstreetmap.org/reverse`, {
          params: {
            lat: latitude,
            lon: longitude,
            format: 'json',
            addressdetails: 1
          }
        });

        const address = response.data.address;
        this.areaName = [
          address.suburb,
          address.city,
          address.state,
          address.country
        ].filter(Boolean).join(', ');

        // Display a more specific area description if available
        if (address.suburb) {
          this.areaName = address.suburb;
        } else if (address.city) {
          this.areaName = address.city;
        } else {
          this.areaName = address.state || address.country || 'Unknown area';
        }
      } catch (error) {
        console.error('Error fetching area name:', error);
        this.areaName = 'Unknown area';
      }

      const accuracyLevel = accuracy <= 100 ? "Strong" : (accuracy <= 500 ? "Moderate" : "Low");
      this.locationDisplay = `
        <div class="location-info">
          <div class="location-item"><strong>Coordinates:</strong> Latitude: ${latitude.toFixed(5)}, Longitude: ${longitude.toFixed(5)}</div>
          <div class="location-item"><strong>Area:</strong> ${this.areaName}</div>
          <div class="location-item"><strong>Accuracy:</strong> We are confident that your location is within ${accuracy.toFixed(2)} meters (${accuracyLevel})</div>
          <div class="location-item"><strong>Displayed Radius:</strong> The circle on the map shows an area of ${accuracy.toFixed(2)} meters around your location</div>
        </div>`;

      this.retryButtonVisible = accuracy > 500;
    },
    showError(error) {
      let errorMessage = '';
      switch (error.code) {
        case error.PERMISSION_DENIED:
          errorMessage = 'User denied the request for Geolocation.';
          break;
        case error.POSITION_UNAVAILABLE:
          errorMessage = 'Location information is unavailable.';
          break;
        case error.TIMEOUT:
          errorMessage = 'The request to get user location timed out.';
          break;
        case error.UNKNOWN_ERROR:
          errorMessage = 'An unknown error occurred.';
          break;
      }
      this.locationDisplay = `Error: ${errorMessage}`;
      this.retryButtonVisible = true;
    },
    handleMapClick(event) {
      if (this.isSettingDangerZone && this.currentLocation) {
        const distance = this.map.distance(this.currentLocation, event.latlng);
        if (distance <= this.dangerZoneRadius) {
          this.dangerZones.push({
            latLng: event.latlng,
            circle: L.circle(event.latlng, {
              color: this.riskLevel === 'high' ? 'red' : (this.riskLevel === 'medium' ? 'orange' : 'green'),
              fillColor: this.riskLevel === 'high' ? '#f00' : (this.riskLevel === 'medium' ? '#ffa500' : '#0f0'),
              fillOpacity: 0.5,
              radius: 100
            }).addTo(this.map),
            riskLevel: this.riskLevel
          });

          this.dangerZoneFormVisible = false;
          this.riskLevelFormVisible = false;
          this.isSettingDangerZone = false;
        } else {
          this.locationDisplay = 'You can only set a danger zone within 1000 meters of your current location.';
        }
      }
    },
    enableRiskLevelForm() {
      this.riskLevelFormVisible = true;
    },
    confirmRiskLevel() {
      this.riskLevelFormVisible = false;
      this.dangerZoneFormVisible = true;
    },
    cancelRiskLevelForm() {
      this.riskLevelFormVisible = false;
    },
    confirmDangerZone() {
      this.isSettingDangerZone = true;
    },
    cancelDangerZoneSetting() {
      this.dangerZoneFormVisible = false;
      this.isSettingDangerZone = false;
    },
    removeDangerZone(index) {
      const zone = this.dangerZones[index];
      if (zone && zone.circle) {
        this.map.removeLayer(zone.circle);
        this.dangerZones.splice(index, 1);
      }
    }
  }
};
</script>

<style scoped>
.container {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 20px;
  max-width: 100%;
  box-sizing: border-box;
  background-color: #f0f0f0;
}

.content {
  width: 100%;
  max-width: 600px;
  margin: 0 auto;
}

.title {
  font-size: 1.8rem;
  margin-bottom: 20px;
  color: #333;
}

.btn {
  width: 100%;
  padding: 10px;
  font-size: 1rem;
  border-radius: 5px;
  border: none;
}

.btn-primary {
  background-color: #007bff;
  color: #fff;
}

.btn-secondary {
  background-color: #6c757d;
  color: #fff;
}

.btn-danger {
  background-color: #dc3545;
  color: #fff;
}

.form-container {
  margin: 20px 0;
  padding: 20px;
  border: 1px solid #ddd;
  border-radius: 10px;
  background-color: #fff;
}

.form-title {
  font-size: 1.2rem;
  margin-bottom: 10px;
}

.form-group {
  margin-bottom: 15px;
}

.form-control {
  width: 100%;
  padding: 10px;
  border-radius: 5px;
  border: 1px solid #ccc;
}

.map {
  height: 300px;
  width: 100%;
  border-radius: 10px;
  margin-top: 20px;
}

.ui-message {
  margin: 10px 0;
  padding: 10px;
  border-radius: 5px;
  font-size: 1rem;
  text-align: center;
  background-color: #ffc107;
  color: #333;
}

.danger-zones {
  margin-top: 20px;
}

.danger-zones-title {
  font-size: 1.2rem;
  margin-bottom: 10px;
}

.danger-zone-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 5px;
  background-color: #fff;
  margin-bottom: 5px;
}

.danger-zone-item .btn-danger {
  padding: 5px;
  font-size: 0.8rem;
}

.location-info {
  font-size: 0.9rem;
}

.location-item {
  margin: 5px 0;
}
</style>