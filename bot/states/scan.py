from aiogram.fsm.state import State, StatesGroup


class ScanStates(StatesGroup):
    """Состояния FSM для процесса выбора параметров и сканирования."""

    waiting_for_url = State()
    waiting_for_mode = State()
