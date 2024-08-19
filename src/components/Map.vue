<template>
  <div class="container">
    <div class="content">
      <h2 class="title">Crime Alert</h2>
      <button v-if="!formVisible && !modalVisible" class="btn btn-primary" @click="showModal">Report</button>

      <!-- Modal -->
      <div v-if="modalVisible" class="modal">
        <div class="modal-content">
          <h4 v-if="currentQuestion">{{ currentQuestion.title }}</h4>
          <div class="modal-options" v-if="currentQuestion">
            <button 
              v-for="(option, index) in currentQuestion.options" 
              :key="index" 
              :class="['btn', { 'selected': selectedOption === option.value }]" 
              @click="selectAnswer(option.value)">
              {{ option.label }}
            </button>
          </div>
          <div class="modal-navigation">
            <button 
              class="btn btn-secondary" 
              @click="previousQuestion"
              :disabled="questionIndex === 0">
              Previous
            </button>
            <button 
              v-if="!isLastQuestion" 
              class="btn btn-primary" 
              @click="nextQuestion"
              :disabled="!selectedOption">
              Next
            </button>
            <button 
              v-if="isLastQuestion" 
              class="btn btn-primary" 
              @click="getLocation">
              Get Location
            </button>
          </div>
        </div>
      </div>

      <div v-if="retryButtonVisible" class="ui-message">
        <p>Failed to fetch accurate location. 
          <button class="btn btn-secondary" @click="retryFetchLocation">Retry</button>
        </p>
      </div>

      <!-- Render map only if the location is available -->
      <div v-if="currentLocation && !riskLevelFormVisible && !dangerZoneFormVisible && !mapVisible" class="map-setup">
        <button class="btn btn-danger" @click="enableRiskLevelForm">Set Danger Zone</button>
      </div>

      <div v-if="mapVisible" id="map" class="map"></div> <!-- Map container -->

      <div v-if="dangerZones.length > 0" class="danger-zones">
        <h4 class="danger-zones-title">Danger Zones</h4>
        <ul>
          <li v-for="(zone, index) in dangerZones" :key="index" class="danger-zone-item">
            Zone {{ index + 1 }} ({{ zone.latLng.lat.toFixed(5) }}, {{ zone.latLng.lng.toFixed(5) }}) - {{ zone.riskLevel }}
            <button class="btn btn-sm btn-danger" @click="removeDangerZone(index)">Remove</button>
          </li>
        </ul>
      </div>

      <div v-if="locationDisplay" class="ui-message">
        <div v-html="locationDisplay"></div>
        <button class="btn btn-secondary" @click="editInformation">Edit Information</button>
        <button class="btn btn-primary" @click="submitInformation">Submit Information</button>
      </div>
    </div>
  </div>
</template>

<script>
import L from 'leaflet';
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
      modalVisible: false,
      mapVisible: false,
      riskLevelFormVisible: false,
      dangerZoneFormVisible: false,
      questionIndex: 0,
      selectedOption: null,
      selectedAnswers: [],
      questions: [
        {
          title: 'What type of crime did you encounter?',
          options: [
            { label: 'Experienced a crime', value: 'experienced' },
            { label: 'Witnessed a crime', value: 'witnessed' },
            { label: 'Heard about a crime', value: 'heard' },
          ]
        },
        {
          title: 'What specific crime did you encounter?',
          options: [
            { label: 'Theft', value: 'theft' },
            { label: 'Assault', value: 'assault' },
            { label: 'Vandalism', value: 'vandalism' },
            { label: 'Burglary', value: 'burglary' },
            { label: 'Robbery', value: 'robbery' },
            { label: 'Fraud', value: 'fraud' },
            { label: 'Harassment', value: 'harassment' },
            { label: 'Other', value: 'other' },
          ]
        },
        {
          title: 'Where did the crime occur?',
          options: [
            { label: 'On the street', value: 'street' },
            { label: 'In a building (residential)', value: 'residential' },
            { label: 'In a building (commercial)', value: 'commercial' },
            { label: 'At a public event', value: 'event' },
            { label: 'In a vehicle', value: 'vehicle' },
            { label: 'In a park or open space', value: 'public place' },
            { label: 'Unknown', value: 'unknown' },
          ]
        },
        {
          title: 'When did the crime occur?',
          options: [
            { label: 'Just now', value: 'just now' },
            { label: 'Within the last hour', value: 'last hour' },
            { label: 'Today', value: 'today' },
            { label: 'Yesterday', value: 'yesterday' },
            { label: 'Last week', value: 'last week' },
          ]
        },
        {
          title: 'How many suspects were involved?',
          options: [
            { label: '1', value: '1 suspect' },
            { label: '2-3', value: '2-3 suspects' },
            { label: '4-5', value: '4-5 suspects' },
            { label: 'More than 5', value: 'more than 5 suspects' },
            { label: 'Unknown', value: 'unknown suspect(s)' },
          ]
        },
        {
          title: 'Were any weapons involved?',
          options: [
            { label: 'Yes, a firearm', value: 'firearm' },
            { label: 'Yes, a knife or sharp object', value: 'knife' },
            { label: 'Yes, another type of weapon', value: 'other' },
            { label: 'No weapons', value: 'unarmed' },
            { label: 'Unknown', value: 'unknown' },
          ]
        },
        {
          title: 'Were there any injuries?',
          options: [
            { label: 'Yes, minor injuries', value: 'minor injuries' },
            { label: 'Yes, serious injuries', value: 'serious injuries' },
            { label: 'Yes, fatal injuries', value: 'fatal injuries' },
            { label: 'No injuries', value: 'no injuries' },
            { label: 'Unknown', value: 'unknown' },
          ]
        },
        {
          title: 'Do you wish to set a danger zone?',
          options: [
            { label: 'Yes', value: 'yes' },
            { label: 'No', value: 'no' }
          ]
        }
      ],
    };
  },
  computed: {
    currentQuestion() {
      return this.questions[this.questionIndex];
    },
    isLastQuestion() {
      return this.questionIndex === this.questions.length - 1;
    }
  },
  methods: {
    showModal() {
      this.modalVisible = true;
    },
    selectAnswer(value) {
      this.selectedOption = value;
    },
    nextQuestion() {
      if (this.questionIndex < this.questions.length - 1) {
        this.selectedAnswers[this.questionIndex] = this.selectedOption;
        this.questionIndex++;
        this.selectedOption = null;
      }
    },
    previousQuestion() {
      if (this.questionIndex > 0) {
        this.selectedAnswers[this.questionIndex] = this.selectedOption;
        this.questionIndex--;
        this.selectedOption = null;
      }
    },
    getLocation() {
      if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(
          (position) => {
            const lat = position.coords.latitude;
            const lng = position.coords.longitude;
            this.currentLocation = { lat, lng };

            // Construct the locationDisplay content based on the selected answers
            const description = this.generateDescription();
            this.locationDisplay = `
              <strong>Location:</strong> (${lat.toFixed(5)}, ${lng.toFixed(5)})<br/>
              <strong>Description:</strong> ${description}
            `;
            this.mapVisible = true;

            // Initialize the map
            this.$nextTick(() => {
              this.initMap();
            });
          },
          () => {
            this.retryButtonVisible = true;
          },
          { enableHighAccuracy: true }
        );
      } else {
        alert('Geolocation is not supported by this browser.');
      }

      this.modalVisible = false;
    },
    generateDescription() {
      const answers = this.selectedAnswers;
      const descriptions = [
        `Type of crime: ${answers[0] || 'Not specified'}`,
        `Specific crime: ${answers[1] || 'Not specified'}`,
        `Location of crime: ${answers[2] || 'Not specified'}`,
        `Time of crime: ${answers[3] || 'Not specified'}`,
        `Number of suspects: ${answers[4] || 'Not specified'}`,
        `Weapons involved: ${answers[6] || 'Not specified'}`,
        `Injuries: ${answers[8] || 'Not specified'}`,
        `Danger zone set: ${answers[10] || 'Not specified'}`,
      ];
      return descriptions.join('<br/>');
    },
    editInformation() {
      this.modalVisible = true;
      this.questionIndex = 0;
      this.selectedOption = this.selectedAnswers[this.questionIndex] || null;
    },
    submitInformation() {
      // Handle the submission of the information
      alert('Information submitted');
    },
    enableRiskLevelForm() {
      this.riskLevelFormVisible = true;
    },
    retryFetchLocation() {
      this.retryButtonVisible = false;
      this.getLocation();
    },
    initMap() {
      this.$nextTick(() => {
        if (!this.map && this.currentLocation) {
          this.map = L.map('map').setView([this.currentLocation.lat, this.currentLocation.lng], 13);

          L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            maxZoom: 19,
          }).addTo(this.map);

          L.marker([this.currentLocation.lat, this.currentLocation.lng])
            .addTo(this.map)
            .bindPopup('You are here')
            .openPopup();

          this.map.on('click', this.handleMapClick);
        }
      });
    },
    handleMapClick(e) {
      if (this.isSettingDangerZone) {
        const latLng = e.latlng;
        const zone = {
          latLng,
          riskLevel: this.riskLevel,
        };

        this.dangerZones.push(zone);
        this.drawDangerZone(latLng, this.dangerZoneRadius);
        this.isSettingDangerZone = false;
      }
    },
    drawDangerZone(latLng, radius) {
      if (this.circle) {
        this.map.removeLayer(this.circle);
      }
      this.circle = L.circle(latLng, {
        color: 'red',
        fillColor: '#f03',
        fillOpacity: 0.5,
        radius: radius,
      }).addTo(this.map);
    },
    removeDangerZone(index) {
      this.dangerZones.splice(index, 1);
      if (this.circle) {
        this.map.removeLayer(this.circle);
      }
    }
  },
  mounted() {
    // Ensure the map is initialized only if the currentLocation is available and mapVisible is true
    if (this.currentLocation && this.mapVisible) {
      this.initMap();
    }
  }
};
</script>

<style scoped>
.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
  font-family: 'Arial', sans-serif;
  color: #fff;
  background-color: #000;
  text-align: center;
}
.content {
  margin-top: 20px;
}
.title {
  font-size: 36px;
  font-weight: bold;
  margin-bottom: 20px;
  color: #ffcc00; /* Yellow title */
}
.btn {
  padding: 10px 20px;
  margin: 5px;
  font-size: 16px;
  cursor: pointer;
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
.selected {
  border: 2px solid #007bff;
}
.modal {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  justify-content: center;
  align-items: center;
}
.modal-content {
  background: white;
  padding: 20px;
  border-radius: 5px;
  text-align: left;
  width: 300px;
}
.map-setup {
  margin-top: 20px;
}
.map {
  height: 400px;
  width: 100%;
  margin: 20px 0;
  border: 2px solid #000;
}
.danger-zones {
  margin-top: 20px;
}
.danger-zone-item {
  margin: 10px 0;
  padding: 10px;
  background-color: #f8f9fa;
  border-radius: 5px;
  text-align: left;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.danger-zones-title {
  font-size: 18px;
  margin-bottom: 10px;
}
.ui-message {
  margin-top: 20px;
  padding: 15px;
  background-color: #000
  ;
  border-radius: 5px;
  text-align: left;
}
</style>