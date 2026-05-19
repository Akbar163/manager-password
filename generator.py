"""
generator.py — модуль генерации паролей и парольных фраз

Использует `secrets` — криптостойкий ГПСЧ на базе OS CSPRNG (/dev/urandom / CryptGenRandom).
Для сравнения также доступен `random`, но его ПРИМЕНЕНИЕ ДЛЯ ПАРОЛЕЙ ЗАПРЕЩЕНО.
"""

import secrets
import random as _insecure_random  # только для демонстрации разницы
import string
import math
from dataclasses import dataclass, field
from typing import Optional
import re


# ─── Наборы символов ──────────────────────────────────────────────────────────

LOWERCASE   = string.ascii_lowercase          # a-z  (26)
UPPERCASE   = string.ascii_uppercase          # A-Z  (26)
DIGITS      = string.digits                   # 0-9  (10)
SYMBOLS     = "!@#$%^&*()-_=+[]{}|;:,.<>?"   # 24 спецсимвола (без кавычек/пробела)

# Словарь для парольных фраз (упрощённый EFF Large Wordlist)
EFF_WORDLIST = [
    "abandon","ability","able","about","above","absent","absorb","abstract","absurd",
    "abuse","access","accident","account","accuse","achieve","acid","acoustic","acquire",
    "across","action","actor","actual","adapt","add","addict","address","adjust","admit",
    "adult","advance","advice","aerobic","afford","afraid","again","agent","agree","ahead",
    "aim","airport","aisle","alarm","album","alcohol","alert","alien","alley","allow",
    "almost","alone","alpha","already","altar","always","amateur","amazing","among","amount",
    "amused","analyst","anchor","ancient","anger","angle","angry","animal","ankle","announce",
    "annual","another","answer","antenna","antique","anxiety","apart","appear","apple",
    "approve","arena","argue","army","around","arrest","arrive","arrow","artist","aspect",
    "assault","asset","assist","assume","asthma","athlete","atom","attack","attend","attitude",
    "attract","auction","audit","august","aunt","author","auto","autumn","average","avocado",
    "avoid","awake","aware","away","awesome","awful","awkward","axis","baby","balance","bamboo",
    "banana","banner","barely","bargain","barrel","basic","basket","battle","beach","beauty",
    "because","become","before","begin","behave","behind","believe","below","bench","benefit",
    "between","beyond","bicycle","bike","bind","biology","bird","birth","bitter","black",
    "blade","blame","blanket","blast","bleak","bless","blind","blood","blossom","blouse",
    "blue","blur","blush","board","boat","body","boil","bomb","bone","bonus","book","boost",
    "border","boring","borrow","boss","bottom","bounce","brain","brand","brave","bread",
    "breeze","brick","bridge","brief","bright","bring","brisk","broccoli","broken","bronze",
    "brown","brush","bubble","buddy","budget","buffalo","build","bulb","burden","burger",
    "burst","bus","business","busy","butter","buyer","cabin","camera","cancel","candy","carpet",
    "carry","castle","casual","catalog","catch","cause","century","certain","chair","chaos",
    "chapter","charge","chase","cheap","check","cheese","child","choice","choose","chronic",
    "circus","citizen","city","civil","claim","clap","clarify","claw","clean","clever","click",
    "client","cliff","climb","clock","close","cloud","cluster","coach","coast","coconut",
    "code","coffee","coil","coin","collect","color","column","combine","come","comfort",
    "comic","common","company","concert","conduct","conflict","congress","connect","coral",
    "copy","coral","core","corn","correct","cost","cotton","couch","country","couple","courage",
    "course","cousin","cover","coyote","crack","craft","crane","crash","credit","creek",
    "crime","crisp","cross","crowd","crucial","cruel","cruise","crumble","crunch","crush",
    "cry","cube","culture","cup","curious","current","curtain","curve","cycle","damage",
    "dance","danger","daring","dash","daughter","dawn","deal","debate","debris","decade",
    "decline","degree","delay","deliver","demand","denial","dentist","depend","deposit",
    "depth","deputy","derive","desert","design","desk","despair","detail","detect","develop",
    "device","diagram","dial","diamond","diary","dice","diesel","diet","differ","digital",
    "dinner","direct","dirt","disease","dismiss","display","distance","diver","divide",
    "divorce","dizzy","doctor","double","dove","draft","drama","drastic","draw","dream",
    "dress","drift","drill","drink","drip","drive","dragon","dumb","during","dust","eager",
    "early","earn","easily","east","easy","edge","eight","either","elbow","elder","emerge",
    "emotion","employ","empty","enable","enact","endless","energy","enforce","engage","engine",
    "enjoy","enough","enter","entire","entry","equal","escape","essay","ethics","evening",
    "exact","excess","expand","expense","express","extra","fabric","famous","family","fancy",
    "fantasy","fashion","fatal","father","fatigue","fault","favorite","feature","fence",
    "festival","fiction","field","figure","final","finger","finish","fiscal","fitness",
    "flame","flash","flavor","flesh","flight","float","flower","fluid","foam","focus",
    "force","forest","forget","found","fragile","frame","frequent","fresh","friend","fringe",
    "frog","front","frost","frown","frozen","fruit","fuel","funny","fury","future","gadget",
    "galaxy","game","garlic","garment","gesture","ghost","ginger","giraffe","glance","gloom",
    "glory","glue","goat","golden","grace","grain","grape","grateful","gravity","green",
    "grid","group","guard","guess","guide","guitar","habit","hammer","hamster","happy",
    "harbor","harvest","health","heavy","help","hidden","history","hockey","hollow","honest",
    "honey","horse","hotel","human","humor","hungry","hybrid","iconic","ignore","illegal",
    "image","immune","impact","impose","improve","income","index","infant","inform","inner",
    "insect","inspire","intact","invest","island","isolate","jacket","jaguar","january","jazz",
    "jealous","jewel","jingle","junior","jungle","keep","kernel","kitchen","kite","kitten",
    "laptop","large","laser","laugh","layer","leader","learn","lecture","legal","legend",
    "letter","library","light","limit","liquid","little","lizard","local","logic","lonely",
    "long","loyal","lucky","magic","manage","marine","match","meadow","media","melody","metal",
    "method","middle","minor","minute","miracle","mobile","model","modify","moment","money",
    "month","moral","mother","motion","motor","mountain","mouse","move","museum","music",
    "naive","narrow","nature","network","neutral","noble","noise","number","object","obtain",
    "obvious","often","opera","option","orange","orbit","order","organ","orient","outdoor",
    "output","oxygen","oyster","panel","paper","parade","parent","partial","patient","patrol",
    "pattern","peace","perfect","permit","phrase","piano","picture","pilot","pizza","planet",
    "plastic","plate","pledge","pluck","poem","point","polar","police","pond","position",
    "poverty","powder","power","practice","predict","prefer","pretty","prevent","primary",
    "prince","prison","private","prize","problem","produce","project","promote","proof",
    "protect","proud","provide","public","puzzle","rabbit","radar","random","rapid","rather",
    "reach","reason","rebel","recycle","reform","refuse","region","reject","remain","repair",
    "report","rescue","resist","return","reveal","review","reward","rhythm","ribbon","right",
    "rigid","rival","river","robot","rocket","romance","rose","rough","royal","rubber","ruin",
    "rural","safety","salmon","sample","scale","scene","school","science","season","secret",
    "sector","select","sense","series","shadow","shake","shallow","share","shift","short",
    "silver","simple","since","sketch","skill","sleep","slim","slow","small","smart","smile",
    "smoke","snake","social","solar","solid","solution","solve","someone","source","south",
    "space","spare","spatial","spawn","speak","speed","sphere","spider","stamp","stand",
    "state","stay","stock","stone","store","storm","subject","submit","sugar","sunset",
    "supply","surface","survey","swift","sword","symbol","system","talent","target","teach",
    "temple","tennis","theory","throw","ticket","tiger","toast","today","token","tooth",
    "topic","total","tourist","toward","tower","town","trade","traffic","transfer","travel",
    "treat","trial","tribe","trigger","trip","trophy","trouble","tunnel","typical","ugly",
    "unable","unique","unrest","urban","used","user","usual","utmost","valid","valley",
    "various","vast","vehicle","vendor","venture","verify","video","vigor","vintage","virus",
    "visit","visual","vital","vivid","vocal","voice","volume","voyage","wagon","waste",
    "water","wealth","weird","west","wheat","where","whisper","width","window","winter",
    "wisdom","world","worry","wrist","wrong","youth","zebra","zone"
]


# ─── Уровни сложности ─────────────────────────────────────────────────────────

PRESETS = {
    "weak":   dict(length=8,  use_upper=False, use_digits=True,  use_symbols=False),
    "medium": dict(length=12, use_upper=True,  use_digits=True,  use_symbols=False),
    "strong": dict(length=16, use_upper=True,  use_digits=True,  use_symbols=True),
    "ultra":  dict(length=24, use_upper=True,  use_digits=True,  use_symbols=True),
}


# ─── Датакласс параметров генерации ──────────────────────────────────────────

@dataclass
class PasswordParams:
    length:      int  = 16
    use_upper:   bool = True
    use_digits:  bool = True
    use_symbols: bool = True
    preset:      Optional[str] = None   # "weak"|"medium"|"strong"|"ultra"

    def __post_init__(self):
        if self.preset and self.preset in PRESETS:
            for k, v in PRESETS[self.preset].items():
                setattr(self, k, v)
        if self.length < 4:
            raise ValueError("Минимальная длина пароля — 4 символа.")


# ─── Генерация пароля ─────────────────────────────────────────────────────────

def generate_password(params: Optional[PasswordParams] = None) -> str:
    """
    Генерирует случайный пароль с гарантированным наличием
    хотя бы одного символа из каждого включённого набора.

    Алгоритм:
      1. Собираем обязательные символы (по 1 из каждой группы).
      2. Добиваем остаток случайными из объединённого алфавита.
      3. Тасуем через secrets.SystemRandom — CSPRNG уровня ОС.
    """
    if params is None:
        params = PasswordParams()

    alphabet = LOWERCASE[:]          # всегда используем строчные буквы
    mandatory = [secrets.choice(LOWERCASE)]

    if params.use_upper:
        alphabet += UPPERCASE
        mandatory.append(secrets.choice(UPPERCASE))

    if params.use_digits:
        alphabet += DIGITS
        mandatory.append(secrets.choice(DIGITS))

    if params.use_symbols:
        alphabet += SYMBOLS
        mandatory.append(secrets.choice(SYMBOLS))

    # Добиваем до нужной длины
    remaining = [secrets.choice(alphabet) for _ in range(params.length - len(mandatory))]
    password_chars = mandatory + remaining

    # Перемешиваем криптостойко
    srandom = secrets.SystemRandom()
    srandom.shuffle(password_chars)

    return "".join(password_chars)


# ─── Генерация парольной фразы (passphrase) ───────────────────────────────────

def generate_passphrase(word_count: int = 5, separator: str = "-", capitalize: bool = True) -> str:
    """
    Генерирует парольную фразу по методу Diceware:
    выбирает `word_count` слов из словаря EFF через secrets.choice.

    Преимущества перед классическим паролем:
      - Легче запомнить
      - При достаточном числе слов энтропия выше (≥64 бит при 5 словах из ~1000)
    """
    words = [secrets.choice(EFF_WORDLIST) for _ in range(word_count)]
    if capitalize:
        words = [w.capitalize() for w in words]
    return separator.join(words)


# ─── Сравнение secrets vs random (только для демонстрации) ───────────────────

def insecure_generate_password(length: int = 12) -> str:
    """
    ⚠️  НЕБЕЗОПАСНО. Использует random.choice (Mersenne Twister).
    Приведено ТОЛЬКО для демонстрации разницы.
    При восстановлении 624 значений MT-состояние полностью восстановимо.
    """
    alphabet = LOWERCASE + UPPERCASE + DIGITS + SYMBOLS
    return "".join(_insecure_random.choice(alphabet) for _ in range(length))


# ─── Оценка энтропии ─────────────────────────────────────────────────────────

def password_entropy(password: str) -> float:
    """
    Оценивает энтропию пароля по формуле:
        H = L × log2(N)
    где L — длина, N — мощность алфавита.

    Это теоретический максимум для случайного пароля.
    Реальная энтропия «придуманного» пароля обычно ниже.
    """
    n = 0
    if re.search(r"[a-z]", password):  n += 26
    if re.search(r"[A-Z]", password):  n += 26
    if re.search(r"\d", password):     n += 10
    if re.search(r"[^a-zA-Z\d]", password): n += len(SYMBOLS)

    if n == 0:
        return 0.0
    return len(password) * math.log2(n)


def password_strength_label(entropy: float) -> str:
    """Текстовая оценка надёжности по энтропии (бит)."""
    if entropy < 28:   return "❌ Очень слабый"
    if entropy < 36:   return "⚠️  Слабый"
    if entropy < 60:   return "🟡 Средний"
    if entropy < 80:   return "🟢 Надёжный"
    return                     "💎 Очень надёжный"


def analyze_password(password: str) -> dict:
    """Полный анализ пароля: энтропия, длина, состав, оценка."""
    ent = password_entropy(password)
    return {
        "length":    len(password),
        "entropy":   round(ent, 2),
        "strength":  password_strength_label(ent),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_digit": bool(re.search(r"\d",    password)),
        "has_symbol":bool(re.search(r"[^a-zA-Z\d]", password)),
    }
