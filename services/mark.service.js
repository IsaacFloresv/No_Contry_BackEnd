import { MarkModel } from "../database/models/index.js";
import associations from "../database/models/associations.js"

//sevicios pasa informacion de  la base de datos al controlador//
export const getMarks = async () => { /* POST /api/exams/marks [TEACHER] */
  try {                   
    return await MarkModel.findAll({
      attributes: [
        "id", "score", "note", "student_id", "exam_id"
      ]
    });//todos los usuarios
  } catch (error) {
    console.error("Error while fetching marks:", error);
    throw new Error("Error fetching marks");
  }
};

export const getMarkById = async (id) => {  
  try { /* GET /api/exams/:id/marks [TEACHER] */
    return await MarkModel.findByPk(id, {
      include: [
        { association: "Users"},
        { association: "Subjects"}
      ]
    });//usuario por id
  } catch (error) {
    console.error("Error while fetching mark:", error);
    throw new Error("Error fetching mark");
  }
};

export const getMarkByStudent = async (student_id) => { //GET /api/marks/current [TUTOR, STUDENT]
  try {
    return await MarkModel.findOne({//busca un mark por id de estudiante
      where: {
        student_id,
      },
    });
  } catch (error) {
    console.error("Error while fetching mark:", error);
    throw new Error("Error fetching mark");
  }
};

export const insertMark = async (markData) => {//agrega una mark // create
  try {
    return await MarkModel.create(markData);
  } catch (error) {
    console.error("Error while insert Mark:", error);
    throw new Error("Error insert Mark");
  }
};
 export const updateMark = async (scoreData) => {
  try {
    return await MarkModel.update(scoreData, { where: { id: student_id } });
  } catch (error) {
    console.error("Error while update mark:", error);
    throw new Error("Error update mark");
  }
}; 

 export const deleteMark = async (studentId) => { /* PUT /api/marks/:id [TEACHER] */
  try {
    return await MarkModel.destroy({ where: { id: studentId.id } });
  } catch (error) {
    console.error("Error while delete mark:", error);
    throw new Error("Error delete mark");
  }
}; 
