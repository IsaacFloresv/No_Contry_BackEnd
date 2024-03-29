import { BannModel } from "../database/models/index.js";

//Metodos CRUD

//Mostrar todos los registros
export const getAllBanns = async (req, res) => {
  try {
    const banns = await BannModel.findAll();
    res.json(banns);
  } catch (error) {
    res.json({ message: error.message });
  }
};

//Mostrar un registro
export const getBanns = async (req, res) => {
  try {
    const banns = await BannModel.findAll({
      where: { id: req.params.id },
    });
    res.json(banns);
  } catch (error) {
    res.json({ message: error.message });
  }
};

//Crear un registro
export const createBanns = async (req, res) => {
  console.log(req.body);
  try {
    await BannModel.create(req.body);
    res.json({
      message: "Registro creado correctamente",
    });
  } catch (error) {
    res.json({ message: error.message });
  }
};

//Actualizar
export const updateBanns = async (req, res) => {
  try {
    BannModel.update(req.body, {
      where: { id: req.params.id },
    });
  } catch (error) {
    res.json({
      message: "Registro actualizado correctamente",
    });
  }
};

//Eliminar
export const deleteBanns = async (req, res) => {
  console.log(req.params.id);
  try {
    BannModel.destroy({
      where: { id_number: req.params.id },
    });
  } catch (error) {
    res.json({ message: error.message });
  }
};
