const mongoose = require('mongoose');

/**
 * Analyst brief (BLUF) schema — mirrors the frontend MitreBrief interface
 * from src/frontend/src/data/mockBriefs.ts
 */
const briefSchema = new mongoose.Schema(
  {
    incidentId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    bottomLine: { type: String, required: true },
    impact: { type: String, required: true },
    keyEvidence: { type: [String], default: [] },
    recommendedFocus: { type: String, required: true },
  },
  {
    timestamps: true,
    toJSON: {
      virtuals: true,
      transform(_doc, ret) {
        delete ret._id;
        delete ret.__v;
        return ret;
      },
    },
  }
);

module.exports = mongoose.model('Brief', briefSchema);
