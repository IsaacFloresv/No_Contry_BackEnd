import db from "../db.js";
import { DataTypes } from "sequelize";

export const ExamModel = db.define(
  "Exams",
  {
    id: { type: DataTypes.INTEGER(11), primaryKey: true, autoIncrement: true },
    score: { type: DataTypes.INTEGER(11), allowNull: false },
    note: { type: DataTypes.STRING(250), allowNull: false },
    subject_id: { type: DataTypes.INTEGER(11), allowNull: false },
    teacher_id: { type: DataTypes.INTEGER(11), allowNull: false },
  },
  {
    timestamps: true,
  }
);
