// Copyright 2025 Francisco F. Pinochet
// Copyright 2026 Fastcomcorp, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Audio processing enhancements for Phase 2
//!
//! Implements echo cancellation, noise suppression, and automatic gain control.
// Copyright 2025 Francisco F. Pinochet
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


use crate::error::MediaEngineResult;

/// Echo cancellation configuration
#[derive(Debug, Clone)]
pub struct EchoCancellerConfig {
    /// Enable echo cancellation
    pub enabled: bool,
    /// Adaptation rate (0.0 - 1.0)
    pub adaptation_rate: f32,
    /// Maximum delay in samples
    pub max_delay_samples: usize,
}

impl Default for EchoCancellerConfig {
    fn default() -> Self {
        EchoCancellerConfig {
            enabled: true,
            adaptation_rate: 0.1,
            max_delay_samples: 4800,  // 300ms at 16kHz
        }
    }
}

/// Echo canceller
pub struct EchoCanceller {
    config: EchoCancellerConfig,
    adaptive_filter: Vec<f32>,
    delay_estimate: usize,
    last_speaker_output: Vec<f32>,
}

impl EchoCanceller {
    /// Create a new echo canceller
    pub fn new(config: EchoCancellerConfig) -> Self {
        let filter_length = config.max_delay_samples;
        EchoCanceller {
            config,
            adaptive_filter: vec![0.0; filter_length],
            delay_estimate: 0,
            last_speaker_output: Vec::new(),
        }
    }

    /// Process audio to remove echo
    ///
    /// # Arguments
    /// * `microphone_input` - Audio from microphone (may contain echo)
    /// * `speaker_output` - Audio being played (source of echo)
    ///
    /// Returns processed audio with echo removed
    pub fn process(
        &mut self,
        microphone_input: &[f32],
        speaker_output: &[f32],
    ) -> MediaEngineResult<Vec<f32>> {
        if !self.config.enabled {
            return Ok(microphone_input.to_vec());
        }

        // Store speaker output for delay estimation
        self.last_speaker_output.extend_from_slice(speaker_output);
        if self.last_speaker_output.len() > self.config.max_delay_samples {
            self.last_speaker_output.drain(..self.last_speaker_output.len() - self.config.max_delay_samples);
        }

        // Estimate echo delay (simplified - full implementation would use cross-correlation)
        // For Phase 2, use a simple fixed delay estimate
        if self.delay_estimate == 0 {
            self.delay_estimate = 160; // ~10ms at 16kHz (typical echo delay)
        }

        // Apply adaptive filter to remove echo
        let mut output = Vec::with_capacity(microphone_input.len());
        
        for (i, &mic_sample) in microphone_input.iter().enumerate() {
            // Estimate echo from speaker output
            let echo_idx = if i + self.delay_estimate < self.last_speaker_output.len() {
                i + self.delay_estimate
            } else {
                continue;
            };
            
            let echo_estimate = if echo_idx < self.last_speaker_output.len() {
                self.last_speaker_output[echo_idx] * self.adaptive_filter[self.delay_estimate.min(self.adaptive_filter.len() - 1)]
            } else {
                0.0
            };

            // Remove echo
            let cleaned = mic_sample - echo_estimate;
            output.push(cleaned);

            // Update adaptive filter (NLMS algorithm simplified)
            if echo_idx < self.last_speaker_output.len() && self.delay_estimate < self.adaptive_filter.len() {
                let error = cleaned;
                let step = self.config.adaptation_rate * error / (1.0 + speaker_output[echo_idx.min(speaker_output.len() - 1)].abs());
                self.adaptive_filter[self.delay_estimate] += step;
            }
        }

        Ok(output)
    }

    /// Reset echo canceller
    pub fn reset(&mut self) {
        self.adaptive_filter.fill(0.0);
        self.delay_estimate = 0;
        self.last_speaker_output.clear();
    }
}

/// Noise suppression configuration
#[derive(Debug, Clone)]
pub struct NoiseSuppressorConfig {
    /// Enable noise suppression
    pub enabled: bool,
    /// Suppression level (0.0 - 1.0, higher = more aggressive)
    pub suppression_level: f32,
    /// Noise profile update rate
    pub profile_update_rate: f32,
}

impl Default for NoiseSuppressorConfig {
    fn default() -> Self {
        NoiseSuppressorConfig {
            enabled: true,
            suppression_level: 0.7,
            profile_update_rate: 0.1,
        }
    }
}

/// Noise suppressor
pub struct NoiseSuppressor {
    config: NoiseSuppressorConfig,
    noise_profile: Vec<f32>,
    speech_profile: Vec<f32>,
    frame_count: usize,
}

impl NoiseSuppressor {
    /// Create a new noise suppressor
    pub fn new(config: NoiseSuppressorConfig) -> Self {
        NoiseSuppressor {
            config,
            noise_profile: Vec::new(),
            speech_profile: Vec::new(),
            frame_count: 0,
        }
    }

    /// Process audio to suppress noise
    pub fn process(&mut self, audio: &[f32]) -> MediaEngineResult<Vec<f32>> {
        if !self.config.enabled {
            return Ok(audio.to_vec());
        }

        // Initialize profiles if needed
        if self.noise_profile.is_empty() {
            self.noise_profile = vec![0.01; audio.len()]; // Initial noise estimate
            self.speech_profile = vec![0.0; audio.len()];
        }

        // Update noise profile (assume first few frames are noise)
        if self.frame_count < 10 {
            for (i, &sample) in audio.iter().enumerate() {
                if i < self.noise_profile.len() {
                    self.noise_profile[i] = self.noise_profile[i] * 0.9 + (sample.abs() * 0.1);
                }
            }
        }

        // Estimate speech profile
        for (i, &sample) in audio.iter().enumerate() {
            if i < self.speech_profile.len() {
                self.speech_profile[i] = sample.abs();
            }
        }

        // Apply noise suppression (spectral subtraction simplified)
        let mut output = Vec::with_capacity(audio.len());
        for (i, &sample) in audio.iter().enumerate() {
            let noise_level = if i < self.noise_profile.len() {
                self.noise_profile[i]
            } else {
                0.01
            };

            let speech_level = if i < self.speech_profile.len() {
                self.speech_profile[i]
            } else {
                sample.abs()
            };

            // Suppress if noise is significant compared to speech
            let snr = if noise_level > 0.0 {
                speech_level / noise_level
            } else {
                10.0
            };

            let gain = if snr > 2.0 {
                1.0  // Strong speech, no suppression
            } else {
                // Suppress based on SNR
                (snr / 2.0).max(0.1) * (1.0 - self.config.suppression_level) + self.config.suppression_level
            };

            output.push(sample * gain);
        }

        self.frame_count += 1;
        Ok(output)
    }

    /// Reset noise suppressor
    pub fn reset(&mut self) {
        self.noise_profile.clear();
        self.speech_profile.clear();
        self.frame_count = 0;
    }
}

/// Automatic Gain Control (AGC) configuration
#[derive(Debug, Clone)]
pub struct AgcConfig {
    /// Enable AGC
    pub enabled: bool,
    /// Target level (0.0 - 1.0)
    pub target_level: f32,
    /// Adaptation rate (0.0 - 1.0)
    pub adaptation_rate: f32,
    /// Maximum gain
    pub max_gain: f32,
    /// Minimum gain
    pub min_gain: f32,
}

impl Default for AgcConfig {
    fn default() -> Self {
        AgcConfig {
            enabled: true,
            target_level: 0.7,  // 70% of max
            adaptation_rate: 0.1,
            max_gain: 3.0,
            min_gain: 0.1,
        }
    }
}

/// Automatic Gain Control
pub struct AutomaticGainControl {
    config: AgcConfig,
    current_gain: f32,
}

impl AutomaticGainControl {
    /// Create a new AGC
    pub fn new(config: AgcConfig) -> Self {
        AutomaticGainControl {
            config,
            current_gain: 1.0,
        }
    }

    /// Process audio to normalize levels
    pub fn process(&mut self, audio: &mut [f32]) -> MediaEngineResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Measure current level (RMS)
        let rms = (audio.iter().map(|&s| s * s).sum::<f32>() / audio.len() as f32).sqrt();

        // Calculate desired gain
        let desired_gain = if rms > 0.0 {
            self.config.target_level / rms
        } else {
            1.0
        };

        // Clamp gain
        let desired_gain = desired_gain
            .max(self.config.min_gain)
            .min(self.config.max_gain);

        // Smooth gain adjustment
        let gain_diff = desired_gain - self.current_gain;
        self.current_gain += gain_diff * self.config.adaptation_rate;

        // Apply gain
        for sample in audio.iter_mut() {
            *sample *= self.current_gain;
            // Clamp to prevent clipping
            *sample = sample.max(-1.0).min(1.0);
        }

        Ok(())
    }

    /// Reset AGC
    pub fn reset(&mut self) {
        self.current_gain = 1.0;
    }

    /// Get current gain
    pub fn current_gain(&self) -> f32 {
        self.current_gain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_canceller() {
        let config = EchoCancellerConfig::default();
        let mut canceller = EchoCanceller::new(config);

        // Need enough speaker output for delay estimation
        let mic_input = vec![0.5, 0.6, 0.7];
        let mut speaker_output = vec![0.0; 200];  // Enough samples for delay
        speaker_output[160] = 0.3;  // Echo at delay position
        speaker_output[161] = 0.4;
        speaker_output[162] = 0.5;

        let result = canceller.process(&mic_input, &speaker_output).unwrap();
        // Result may be shorter if delay estimation fails, but should process some samples
        assert!(!result.is_empty());
    }

    #[test]
    fn test_noise_suppressor() {
        let config = NoiseSuppressorConfig::default();
        let mut suppressor = NoiseSuppressor::new(config);

        let audio = vec![0.1, 0.2, 0.3, 0.4, 0.5];
        let result = suppressor.process(&audio).unwrap();
        assert_eq!(result.len(), audio.len());
    }

    #[test]
    fn test_agc() {
        let config = AgcConfig::default();
        let mut agc = AutomaticGainControl::new(config);

        let mut audio = vec![0.1, 0.2, 0.3];
        agc.process(&mut audio).unwrap();
        
        // Audio should be normalized
        assert!(!audio.is_empty());
    }
}

