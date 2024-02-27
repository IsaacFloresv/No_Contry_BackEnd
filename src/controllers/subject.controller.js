import {
  getSubject,
  getSubjectId,
  getSubjectsTeacherId,
  insertSubjects,
  modifySubject,
} from "../services/subject.service.js";
import { encrypt } from "../middlewares/encrypt.js";
import { hashSync } from "bcrypt";

/* CREATE TABLE `Subjects` (
    `id` int(11) NOT NULL,
    `name` varchar(255) NOT NULL,
    `grade` varchar(255) NOT NULL,
    `divition` varchar(255) NOT NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=latin1;
   */
export const getSubjects = async (req, res) => {
  try {
    const subjects = await getSubject();
    const RESPONSE = {
      count: subjects.length,
      subjects,
      detail: `/api/subjects/${subjects[0].id}`
    };
    return res.status(200).json(RESPONSE);
  } catch (error) {
    res.status(500).json({ Error: error });
  }
};
export const getSubjectById = async (req, res) => {
  try {
    const SUBJECT_ID = req.params.id;
    const subject = await getSubjectId(SUBJECT_ID);
    return res.status(200).json(subject);
  } catch (error) {
    res.status(500).json({ Error: error });
  }
};
export const getSubjectsByTeacherId = async (req, res) => {
  try {
    const TEACHER_ID = req.params.teacher_id;
    console.log(TEACHER_ID);
    const subjects = await getSubjectsTeacherId(TEACHER_ID);
    return res.status(200).json(subjects);
  } catch (error) {
    res.status(500).json({ Error: error });
  }
};
export const createSubject = async (req, res) => {
  try {
    const result = await insertSubjects({
         ...req.body,
         password: hashSync(req.body.password, 12),
        }
    );
    return res.status(201).json(result, { msg: `Created subject` });
  } catch (error) {
    return res.status(500).json({ Error: error });
  }
};
export const updateSubject = async (req, res) => {
  try {
    const NEW_DATA = req.body;
    const result = await modifySubject(NEW_DATA);
    return res.status(201).json(result);
  } catch (error) {
    return res.status(500).json({ Error: error });
  }
};
