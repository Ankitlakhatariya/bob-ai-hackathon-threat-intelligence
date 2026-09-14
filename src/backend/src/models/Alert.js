const mongoose = require('mongoose');

/**
 * Alert schema — mirrors the frontend Alert interface from
 * src/frontend/src/types/alert.ts
 */
const alertSchema = new mongoose.Schema(
  {
    alertId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    teamId: { type: String, required: true },
    title: { type: String, required: true },
    description: { type: String, required: true },
    source: {
      type: String,
      enum: ['siem', 'edr', 'network-sensor', 'threat-feed'],
      required: true,
    },
    sourceLabel: { type: String, required: true },
    timestamp: { type: Date, required: true },
    severity: {
      type: String,
      enum: ['critical', 'high', 'medium', 'low'],
      required: true,
    },
    status: {
      type: String,
      enum: ['open', 'investigating', 'resolved', 'false-positive'],
      default: 'open',
    },
    riskScore: {
      type: Number,
      min: 0,
      max: 100,
      required: true,
    },
    relatedIncidentId: { type: String, default: null },
    mitreTechniques: { type: [String], default: [] },
    indicators: { type: [String], default: [] },
  },
  {
    timestamps: true,
    toJSON: {
      virtuals: true,
      transform(_doc, ret) {
        // Map alertId → id to match the frontend contract
        ret.id = ret.alertId;
        ret.timestamp = ret.timestamp.toISOString();
        delete ret.alertId;
        delete ret._id;
        delete ret.__v;
        return ret;
      },
    },
  }
);

module.exports = mongoose.model('Alert', alertSchema);
