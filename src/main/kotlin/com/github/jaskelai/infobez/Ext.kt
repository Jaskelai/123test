package com.github.jaskelai.infobez

import java.math.BigDecimal
import java.math.BigInteger
import java.math.MathContext
import kotlin.math.abs
import kotlin.math.log10
import kotlin.math.pow

// наиболее точное(с небольшой погрешностью) вычисление корня из куба
fun cubeRoot(input: BigInteger): BigInteger = root(3, BigDecimal(input)).toBigInteger()

private fun root(n: Int, x: BigDecimal): BigDecimal {

    var s = BigDecimal(x.toDouble().pow(1.0 / n))

    val nth = BigDecimal(n)

    val xhighpr = scalePrec(x, 2)
    val mc = MathContext(2 + x.precision())
    val eps: Double = x.ulp().toDouble() / (2 * n * x.toDouble())

    while (true) {
        var c = xhighpr.divide(s.pow(n - 1), mc)
        c = s.subtract(c)
        val locmc = MathContext(c.precision())
        c = c.divide(nth, locmc)
        s = s.subtract(c)
        if (abs(c.toDouble() / s.toDouble()) < eps) {
            break
        }
    }
    return s.round(MathContext(err2prec(eps)))
}

private fun scalePrec(x: BigDecimal, d: Int): BigDecimal {
    return x.setScale(d + x.scale())
}

private fun err2prec(xerr: Double): Int {
    return 1 + log10(abs(0.5 / xerr)).toInt()
}