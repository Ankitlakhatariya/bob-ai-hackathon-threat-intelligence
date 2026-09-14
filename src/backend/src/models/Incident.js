const mongoose = require('mongoose');

/**
 * Incident schema — mirrors the frontend Incident interface from
 * src/frontend/src/types/incident.ts
 */
const incidentSchema = new mongoose.Schema(
  {
    incidentId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    title: { type: String, required: true },
    summary: { type: String, required: true },
    severity: {
      type: String,
      enum: ['critical', 'high', 'medium', 'low'],
      required: true,
    },
    status: {
      type: String,
      enum: ['active', 'investigating', 'resolved'],
      default: 'active',
    },
    confidence: {
      type: Number,
      min: 0,
      max: 100,
      required: true,
    },
    openedAt: { type: Date, required: true },
    updatedAt: { type: Date, required: true },
    alertIds: { type: [String], default: [] },
    mitreTechniques: { type: [String], default: [] },
  },
  {
    timestamps: true,
    toJSON: {
      virtuals: true,
      transform(_doc, ret) {
        ret.id = ret.incidentId;
        ret.openedAt = ret.openedAt.toISOString();
        ret.updatedAt = ret.updatedAt.toISOString();
        delete ret.incidentId;
        delete ret._id;
        delete ret.__v;
        return ret;
      },
    },
  }
);

module.exports = mongoose.model('Incident', incidentSchema);
