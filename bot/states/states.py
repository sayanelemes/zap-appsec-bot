from aiogram.fsm.state import State, StatesGroup


class ProfileForm(StatesGroup):
    """
    Пример машины состояний (FSM) для заполнения анкеты / профиля.
    Демонстрирует переходы по шагам, валидацию и сохранение данных.
    """

    waiting_for_name = State()
    waiting_for_age = State()
    waiting_for_bio = State()
