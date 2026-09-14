const mongoose = require('mongoose');

/**
 * MITRE ATT&CK technique catalogue — mirrors the frontend MitreTechnique
 * interface from src/frontend/src/data/mockMitre.ts
 */
const mitreTechniqueSchema = new mongoose.Schema(
  {
    techniqueId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    name: { type: String, required: true },
    tactics: { type: [String], required: true },
    description: { type: String, required: true },
    url: { type: String, required: true },
  },
  {
    timestamps: true,
    toJSON: {
      virtuals: true,
      transform(_doc, ret) {
        ret.id = ret.techniqueId;
        delete ret.techniqueId;
        delete ret._id;
        delete ret.__v;
        return ret;
      },
    },
  }
);

module.exports = mongoose.model('MitreTechnique', mitreTechniqueSchema);
