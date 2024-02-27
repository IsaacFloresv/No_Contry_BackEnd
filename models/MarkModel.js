import db from "../db.js";
import { DataTypes } from "sequelize";

export const MarkModel = db.define(
  "Marks",
  {
    id: { type: DataTypes.INTEGER(11), primaryKey: true, autoIncrement: true },
    score: { type: DataTypes.INTEGER(11), allowNull: false },
    note: { type: DataTypes.STRING(250), allowNull: false },
    student_id: { type: DataTypes.INTEGER },
    exam_id: { type: DataTypes.INTEGER },
  },
  {
    timestamps: true,
  }
);
