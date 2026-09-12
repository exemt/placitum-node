// Детерминированный генератор псевдослучайных чисел.
//
// Math.random() здесь не годится: прогон, который нельзя повторить, нельзя ни
// сравнить с предыдущим, ни воспроизвести при падении. Весь корпус собирается
// от одного зерна CORPUS_SEED, и оно пишется в манифест прогона.
//
// splitmix32 выбран за скорость и за то, что укладывается в десять строк:
// качество распределения здесь важно ровно настолько, чтобы трафик не имел
// заметных периодов, а криптостойкость не нужна вовсе.

export function seeded(seed) {
    let s = seed >>> 0;

    return function next() {
        s = (s + 0x9e3779b9) >>> 0;
        let t = s;
        t = Math.imul(t ^ (t >>> 16), 0x21f0aaad);
        t = Math.imul(t ^ (t >>> 15), 0x735a2d97);
        return ((t ^ (t >>> 15)) >>> 0) / 4294967296;
    };
}

export function intBelow(rnd, n) {
    return Math.floor(rnd() * n);
}

export function between(rnd, min, max) {
    return min + Math.floor(rnd() * (max - min + 1));
}

export function pick(rnd, arr) {
    return arr[Math.floor(rnd() * arr.length)];
}

export function chance(rnd, p) {
    return rnd() < p;
}

const HEX = '0123456789abcdef';

export function hex(rnd, n) {
    let out = '';
    for (let i = 0; i < n; i++) {
        out += HEX[Math.floor(rnd() * 16)];
    }
    return out;
}

const ALNUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

export function alnum(rnd, n) {
    let out = '';
    for (let i = 0; i < n; i++) {
        out += ALNUM[Math.floor(rnd() * 62)];
    }
    return out;
}

// Перемешивание на месте. Нужно для порядка заголовков: протокол обещает
// инспектору заголовки в порядке получения, значит постоянного порядка в
// нагрузке быть не должно.
export function shuffle(rnd, arr) {
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(rnd() * (i + 1));
        const t = arr[i];
        arr[i] = arr[j];
        arr[j] = t;
    }
    return arr;
}
