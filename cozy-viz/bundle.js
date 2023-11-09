(() => {
  // http-url:https://unpkg.com/preact@latest?module
  var n;
  var l;
  var u;
  var t;
  var i;
  var o;
  var r;
  var f;
  var e;
  var c = {};
  var s = [];
  var a = /acit|ex(?:s|g|n|p|$)|rph|grid|ows|mnc|ntw|ine[ch]|zoo|^ord|itera/i;
  var v = Array.isArray;
  function h(n11, l10) {
    for (var u9 in l10)
      n11[u9] = l10[u9];
    return n11;
  }
  function p(n11) {
    var l10 = n11.parentNode;
    l10 && l10.removeChild(n11);
  }
  function y(l10, u9, t14) {
    var i9, o11, r8, f10 = {};
    for (r8 in u9)
      "key" == r8 ? i9 = u9[r8] : "ref" == r8 ? o11 = u9[r8] : f10[r8] = u9[r8];
    if (arguments.length > 2 && (f10.children = arguments.length > 3 ? n.call(arguments, 2) : t14), "function" == typeof l10 && null != l10.defaultProps)
      for (r8 in l10.defaultProps)
        void 0 === f10[r8] && (f10[r8] = l10.defaultProps[r8]);
    return d(l10, f10, i9, o11, null);
  }
  function d(n11, t14, i9, o11, r8) {
    var f10 = { type: n11, props: t14, key: i9, ref: o11, __k: null, __: null, __b: 0, __e: null, __d: void 0, __c: null, __h: null, constructor: void 0, __v: null == r8 ? ++u : r8, __i: -1 };
    return null == r8 && null != l.vnode && l.vnode(f10), f10;
  }
  function _() {
    return { current: null };
  }
  function k(n11) {
    return n11.children;
  }
  function m(n11, l10) {
    this.props = n11, this.context = l10;
  }
  function b(n11, l10) {
    if (null == l10)
      return n11.__ ? b(n11.__, n11.__i + 1) : null;
    for (var u9; l10 < n11.__k.length; l10++)
      if (null != (u9 = n11.__k[l10]) && null != u9.__e)
        return u9.__e;
    return "function" == typeof n11.type ? b(n11) : null;
  }
  function g(n11) {
    var l10, u9;
    if (null != (n11 = n11.__) && null != n11.__c) {
      for (n11.__e = n11.__c.base = null, l10 = 0; l10 < n11.__k.length; l10++)
        if (null != (u9 = n11.__k[l10]) && null != u9.__e) {
          n11.__e = n11.__c.base = u9.__e;
          break;
        }
      return g(n11);
    }
  }
  function w(n11) {
    (!n11.__d && (n11.__d = true) && i.push(n11) && !x.__r++ || o !== l.debounceRendering) && ((o = l.debounceRendering) || r)(x);
  }
  function x() {
    var n11, l10, u9, t14, o11, r8, e19, c9, s10;
    for (i.sort(f); n11 = i.shift(); )
      n11.__d && (l10 = i.length, t14 = void 0, o11 = void 0, r8 = void 0, c9 = (e19 = (u9 = n11).__v).__e, (s10 = u9.__P) && (t14 = [], o11 = [], (r8 = h({}, e19)).__v = e19.__v + 1, z(s10, r8, e19, u9.__n, void 0 !== s10.ownerSVGElement, null != e19.__h ? [c9] : null, t14, null == c9 ? b(e19) : c9, e19.__h, o11), r8.__.__k[r8.__i] = r8, L(t14, r8, o11), r8.__e != c9 && g(r8)), i.length > l10 && i.sort(f));
    x.__r = 0;
  }
  function C(n11, l10, u9, t14, i9, o11, r8, f10, e19, a8, h9) {
    var p9, y9, _6, m11, g8, w9, x10, C8, $6, D7 = 0, H8 = t14 && t14.__k || s, I7 = H8.length, T8 = I7, j8 = l10.length;
    for (u9.__k = [], p9 = 0; p9 < j8; p9++)
      null != (m11 = u9.__k[p9] = null == (m11 = l10[p9]) || "boolean" == typeof m11 || "function" == typeof m11 ? null : m11.constructor == String || "number" == typeof m11 || "bigint" == typeof m11 ? d(null, m11, null, null, m11) : v(m11) ? d(k, { children: m11 }, null, null, null) : m11.__b > 0 ? d(m11.type, m11.props, m11.key, m11.ref ? m11.ref : null, m11.__v) : m11) ? (m11.__ = u9, m11.__b = u9.__b + 1, m11.__i = p9, -1 === (C8 = A(m11, H8, x10 = p9 + D7, T8)) ? _6 = c : (_6 = H8[C8] || c, H8[C8] = void 0, T8--), z(n11, m11, _6, i9, o11, r8, f10, e19, a8, h9), g8 = m11.__e, (y9 = m11.ref) && _6.ref != y9 && (_6.ref && N(_6.ref, null, m11), h9.push(y9, m11.__c || g8, m11)), null == w9 && null != g8 && (w9 = g8), ($6 = _6 === c || null === _6.__v) ? -1 == C8 && D7-- : C8 !== x10 && (C8 === x10 + 1 ? D7++ : C8 > x10 ? T8 > j8 - x10 ? D7 += C8 - x10 : D7-- : D7 = C8 < x10 && C8 == x10 - 1 ? C8 - x10 : 0), x10 = p9 + D7, "function" == typeof m11.type ? (C8 !== x10 || _6.__k === m11.__k ? e19 = P(m11, e19, n11) : void 0 !== m11.__d ? e19 = m11.__d : g8 && (e19 = g8.nextSibling), m11.__d = void 0) : g8 && (e19 = C8 !== x10 || $6 ? S(n11, g8, e19) : g8.nextSibling), "function" == typeof u9.type && (u9.__d = e19)) : (_6 = H8[p9]) && null == _6.key && _6.__e && (_6.__e == e19 && (e19 = b(_6), "function" == typeof u9.type && (u9.__d = e19)), O(_6, _6, false), H8[p9] = null);
    for (u9.__e = w9, p9 = I7; p9--; )
      null != H8[p9] && ("function" == typeof u9.type && null != H8[p9].__e && H8[p9].__e == e19 && (u9.__d = H8[p9].__e.nextSibling), O(H8[p9], H8[p9]));
  }
  function P(n11, l10, u9) {
    for (var t14, i9 = n11.__k, o11 = 0; i9 && o11 < i9.length; o11++)
      (t14 = i9[o11]) && (t14.__ = n11, l10 = "function" == typeof t14.type ? P(t14, l10, u9) : S(u9, t14.__e, l10));
    return l10;
  }
  function S(n11, l10, u9) {
    return l10 != u9 && n11.insertBefore(l10, u9 || null), l10.nextSibling;
  }
  function A(n11, l10, u9, t14) {
    var i9 = n11.key, o11 = n11.type, r8 = u9 - 1, f10 = u9 + 1, e19 = l10[u9];
    if (null === e19 || e19 && i9 == e19.key && o11 === e19.type)
      return u9;
    if (t14 > (null != e19 ? 1 : 0))
      for (; r8 >= 0 || f10 < l10.length; ) {
        if (r8 >= 0) {
          if ((e19 = l10[r8]) && i9 == e19.key && o11 === e19.type)
            return r8;
          r8--;
        }
        if (f10 < l10.length) {
          if ((e19 = l10[f10]) && i9 == e19.key && o11 === e19.type)
            return f10;
          f10++;
        }
      }
    return -1;
  }
  function D(n11, l10, u9, t14, i9) {
    var o11;
    for (o11 in u9)
      "children" === o11 || "key" === o11 || o11 in l10 || I(n11, o11, null, u9[o11], t14);
    for (o11 in l10)
      i9 && "function" != typeof l10[o11] || "children" === o11 || "key" === o11 || "value" === o11 || "checked" === o11 || u9[o11] === l10[o11] || I(n11, o11, l10[o11], u9[o11], t14);
  }
  function H(n11, l10, u9) {
    "-" === l10[0] ? n11.setProperty(l10, null == u9 ? "" : u9) : n11[l10] = null == u9 ? "" : "number" != typeof u9 || a.test(l10) ? u9 : u9 + "px";
  }
  function I(n11, l10, u9, t14, i9) {
    var o11;
    n:
      if ("style" === l10) {
        if ("string" == typeof u9)
          n11.style.cssText = u9;
        else {
          if ("string" == typeof t14 && (n11.style.cssText = t14 = ""), t14)
            for (l10 in t14)
              u9 && l10 in u9 || H(n11.style, l10, "");
          if (u9)
            for (l10 in u9)
              t14 && u9[l10] === t14[l10] || H(n11.style, l10, u9[l10]);
        }
      } else if ("o" === l10[0] && "n" === l10[1])
        o11 = l10 !== (l10 = l10.replace(/(PointerCapture)$|Capture$/, "$1")), l10 = l10.toLowerCase() in n11 ? l10.toLowerCase().slice(2) : l10.slice(2), n11.l || (n11.l = {}), n11.l[l10 + o11] = u9, u9 ? t14 ? u9.u = t14.u : (u9.u = Date.now(), n11.addEventListener(l10, o11 ? j : T, o11)) : n11.removeEventListener(l10, o11 ? j : T, o11);
      else if ("dangerouslySetInnerHTML" !== l10) {
        if (i9)
          l10 = l10.replace(/xlink(H|:h)/, "h").replace(/sName$/, "s");
        else if ("width" !== l10 && "height" !== l10 && "href" !== l10 && "list" !== l10 && "form" !== l10 && "tabIndex" !== l10 && "download" !== l10 && "rowSpan" !== l10 && "colSpan" !== l10 && "role" !== l10 && l10 in n11)
          try {
            n11[l10] = null == u9 ? "" : u9;
            break n;
          } catch (n12) {
          }
        "function" == typeof u9 || (null == u9 || false === u9 && "-" !== l10[4] ? n11.removeAttribute(l10) : n11.setAttribute(l10, u9));
      }
  }
  function T(n11) {
    var u9 = this.l[n11.type + false];
    if (n11.t) {
      if (n11.t <= u9.u)
        return;
    } else
      n11.t = Date.now();
    return u9(l.event ? l.event(n11) : n11);
  }
  function j(n11) {
    return this.l[n11.type + true](l.event ? l.event(n11) : n11);
  }
  function z(n11, u9, t14, i9, o11, r8, f10, e19, c9, s10) {
    var a8, p9, y9, d10, _6, b10, g8, w9, x10, P9, $6, S7, A9, D7, H8, I7 = u9.type;
    if (void 0 !== u9.constructor)
      return null;
    null != t14.__h && (c9 = t14.__h, e19 = u9.__e = t14.__e, u9.__h = null, r8 = [e19]), (a8 = l.__b) && a8(u9);
    n:
      if ("function" == typeof I7)
        try {
          if (w9 = u9.props, x10 = (a8 = I7.contextType) && i9[a8.__c], P9 = a8 ? x10 ? x10.props.value : a8.__ : i9, t14.__c ? g8 = (p9 = u9.__c = t14.__c).__ = p9.__E : ("prototype" in I7 && I7.prototype.render ? u9.__c = p9 = new I7(w9, P9) : (u9.__c = p9 = new m(w9, P9), p9.constructor = I7, p9.render = q), x10 && x10.sub(p9), p9.props = w9, p9.state || (p9.state = {}), p9.context = P9, p9.__n = i9, y9 = p9.__d = true, p9.__h = [], p9._sb = []), null == p9.__s && (p9.__s = p9.state), null != I7.getDerivedStateFromProps && (p9.__s == p9.state && (p9.__s = h({}, p9.__s)), h(p9.__s, I7.getDerivedStateFromProps(w9, p9.__s))), d10 = p9.props, _6 = p9.state, p9.__v = u9, y9)
            null == I7.getDerivedStateFromProps && null != p9.componentWillMount && p9.componentWillMount(), null != p9.componentDidMount && p9.__h.push(p9.componentDidMount);
          else {
            if (null == I7.getDerivedStateFromProps && w9 !== d10 && null != p9.componentWillReceiveProps && p9.componentWillReceiveProps(w9, P9), !p9.__e && (null != p9.shouldComponentUpdate && false === p9.shouldComponentUpdate(w9, p9.__s, P9) || u9.__v === t14.__v)) {
              for (u9.__v !== t14.__v && (p9.props = w9, p9.state = p9.__s, p9.__d = false), u9.__e = t14.__e, u9.__k = t14.__k, u9.__k.forEach(function(n12) {
                n12 && (n12.__ = u9);
              }), $6 = 0; $6 < p9._sb.length; $6++)
                p9.__h.push(p9._sb[$6]);
              p9._sb = [], p9.__h.length && f10.push(p9);
              break n;
            }
            null != p9.componentWillUpdate && p9.componentWillUpdate(w9, p9.__s, P9), null != p9.componentDidUpdate && p9.__h.push(function() {
              p9.componentDidUpdate(d10, _6, b10);
            });
          }
          if (p9.context = P9, p9.props = w9, p9.__P = n11, p9.__e = false, S7 = l.__r, A9 = 0, "prototype" in I7 && I7.prototype.render) {
            for (p9.state = p9.__s, p9.__d = false, S7 && S7(u9), a8 = p9.render(p9.props, p9.state, p9.context), D7 = 0; D7 < p9._sb.length; D7++)
              p9.__h.push(p9._sb[D7]);
            p9._sb = [];
          } else
            do {
              p9.__d = false, S7 && S7(u9), a8 = p9.render(p9.props, p9.state, p9.context), p9.state = p9.__s;
            } while (p9.__d && ++A9 < 25);
          p9.state = p9.__s, null != p9.getChildContext && (i9 = h(h({}, i9), p9.getChildContext())), y9 || null == p9.getSnapshotBeforeUpdate || (b10 = p9.getSnapshotBeforeUpdate(d10, _6)), C(n11, v(H8 = null != a8 && a8.type === k && null == a8.key ? a8.props.children : a8) ? H8 : [H8], u9, t14, i9, o11, r8, f10, e19, c9, s10), p9.base = u9.__e, u9.__h = null, p9.__h.length && f10.push(p9), g8 && (p9.__E = p9.__ = null);
        } catch (n12) {
          u9.__v = null, c9 || null != r8 ? (u9.__e = e19, u9.__h = !!c9, r8[r8.indexOf(e19)] = null) : (u9.__e = t14.__e, u9.__k = t14.__k), l.__e(n12, u9, t14);
        }
      else
        null == r8 && u9.__v === t14.__v ? (u9.__k = t14.__k, u9.__e = t14.__e) : u9.__e = M(t14.__e, u9, t14, i9, o11, r8, f10, c9, s10);
    (a8 = l.diffed) && a8(u9);
  }
  function L(n11, u9, t14) {
    u9.__d = void 0;
    for (var i9 = 0; i9 < t14.length; i9++)
      N(t14[i9], t14[++i9], t14[++i9]);
    l.__c && l.__c(u9, n11), n11.some(function(u10) {
      try {
        n11 = u10.__h, u10.__h = [], n11.some(function(n12) {
          n12.call(u10);
        });
      } catch (n12) {
        l.__e(n12, u10.__v);
      }
    });
  }
  function M(l10, u9, t14, i9, o11, r8, f10, e19, s10) {
    var a8, h9, y9, d10 = t14.props, _6 = u9.props, k9 = u9.type, m11 = 0;
    if ("svg" === k9 && (o11 = true), null != r8) {
      for (; m11 < r8.length; m11++)
        if ((a8 = r8[m11]) && "setAttribute" in a8 == !!k9 && (k9 ? a8.localName === k9 : 3 === a8.nodeType)) {
          l10 = a8, r8[m11] = null;
          break;
        }
    }
    if (null == l10) {
      if (null === k9)
        return document.createTextNode(_6);
      l10 = o11 ? document.createElementNS("http://www.w3.org/2000/svg", k9) : document.createElement(k9, _6.is && _6), r8 = null, e19 = false;
    }
    if (null === k9)
      d10 === _6 || e19 && l10.data === _6 || (l10.data = _6);
    else {
      if (r8 = r8 && n.call(l10.childNodes), h9 = (d10 = t14.props || c).dangerouslySetInnerHTML, y9 = _6.dangerouslySetInnerHTML, !e19) {
        if (null != r8)
          for (d10 = {}, m11 = 0; m11 < l10.attributes.length; m11++)
            d10[l10.attributes[m11].name] = l10.attributes[m11].value;
        (y9 || h9) && (y9 && (h9 && y9.__html == h9.__html || y9.__html === l10.innerHTML) || (l10.innerHTML = y9 && y9.__html || ""));
      }
      if (D(l10, _6, d10, o11, e19), y9)
        u9.__k = [];
      else if (C(l10, v(m11 = u9.props.children) ? m11 : [m11], u9, t14, i9, o11 && "foreignObject" !== k9, r8, f10, r8 ? r8[0] : t14.__k && b(t14, 0), e19, s10), null != r8)
        for (m11 = r8.length; m11--; )
          null != r8[m11] && p(r8[m11]);
      e19 || ("value" in _6 && void 0 !== (m11 = _6.value) && (m11 !== l10.value || "progress" === k9 && !m11 || "option" === k9 && m11 !== d10.value) && I(l10, "value", m11, d10.value, false), "checked" in _6 && void 0 !== (m11 = _6.checked) && m11 !== l10.checked && I(l10, "checked", m11, d10.checked, false));
    }
    return l10;
  }
  function N(n11, u9, t14) {
    try {
      "function" == typeof n11 ? n11(u9) : n11.current = u9;
    } catch (n12) {
      l.__e(n12, t14);
    }
  }
  function O(n11, u9, t14) {
    var i9, o11;
    if (l.unmount && l.unmount(n11), (i9 = n11.ref) && (i9.current && i9.current !== n11.__e || N(i9, null, u9)), null != (i9 = n11.__c)) {
      if (i9.componentWillUnmount)
        try {
          i9.componentWillUnmount();
        } catch (n12) {
          l.__e(n12, u9);
        }
      i9.base = i9.__P = null, n11.__c = void 0;
    }
    if (i9 = n11.__k)
      for (o11 = 0; o11 < i9.length; o11++)
        i9[o11] && O(i9[o11], u9, t14 || "function" != typeof n11.type);
    t14 || null == n11.__e || p(n11.__e), n11.__ = n11.__e = n11.__d = void 0;
  }
  function q(n11, l10, u9) {
    return this.constructor(n11, u9);
  }
  function B(u9, t14, i9) {
    var o11, r8, f10, e19;
    l.__ && l.__(u9, t14), r8 = (o11 = "function" == typeof i9) ? null : i9 && i9.__k || t14.__k, f10 = [], e19 = [], z(t14, u9 = (!o11 && i9 || t14).__k = y(k, null, [u9]), r8 || c, c, void 0 !== t14.ownerSVGElement, !o11 && i9 ? [i9] : r8 ? null : t14.firstChild ? n.call(t14.childNodes) : null, f10, !o11 && i9 ? i9 : r8 ? r8.__e : t14.firstChild, o11, e19), L(f10, u9, e19);
  }
  n = s.slice, l = { __e: function(n11, l10, u9, t14) {
    for (var i9, o11, r8; l10 = l10.__; )
      if ((i9 = l10.__c) && !i9.__)
        try {
          if ((o11 = i9.constructor) && null != o11.getDerivedStateFromError && (i9.setState(o11.getDerivedStateFromError(n11)), r8 = i9.__d), null != i9.componentDidCatch && (i9.componentDidCatch(n11, t14 || {}), r8 = i9.__d), r8)
            return i9.__E = i9;
        } catch (l11) {
          n11 = l11;
        }
    throw n11;
  } }, u = 0, t = function(n11) {
    return null != n11 && null == n11.constructor;
  }, m.prototype.setState = function(n11, l10) {
    var u9;
    u9 = null != this.__s && this.__s !== this.state ? this.__s : this.__s = h({}, this.state), "function" == typeof n11 && (n11 = n11(h({}, u9), this.props)), n11 && h(u9, n11), null != n11 && this.__v && (l10 && this._sb.push(l10), w(this));
  }, m.prototype.forceUpdate = function(n11) {
    this.__v && (this.__e = true, n11 && this.__h.push(n11), w(this));
  }, m.prototype.render = k, i = [], r = "function" == typeof Promise ? Promise.prototype.then.bind(Promise.resolve()) : setTimeout, f = function(n11, l10) {
    return n11.__v.__b - l10.__v.__b;
  }, x.__r = 0, e = 0;

  // http-url:https://unpkg.com/htm@latest?module
  var n2 = function(t14, s10, r8, e19) {
    var u9;
    s10[0] = 0;
    for (var h9 = 1; h9 < s10.length; h9++) {
      var p9 = s10[h9++], a8 = s10[h9] ? (s10[0] |= p9 ? 1 : 2, r8[s10[h9++]]) : s10[++h9];
      3 === p9 ? e19[0] = a8 : 4 === p9 ? e19[1] = Object.assign(e19[1] || {}, a8) : 5 === p9 ? (e19[1] = e19[1] || {})[s10[++h9]] = a8 : 6 === p9 ? e19[1][s10[++h9]] += a8 + "" : p9 ? (u9 = t14.apply(a8, n2(t14, a8, r8, ["", null])), e19.push(u9), a8[0] ? s10[0] |= 2 : (s10[h9 - 2] = 0, s10[h9] = u9)) : e19.push(a8);
    }
    return e19;
  };
  var t2 = /* @__PURE__ */ new Map();
  function htm_latest_module_default(s10) {
    var r8 = t2.get(this);
    return r8 || (r8 = /* @__PURE__ */ new Map(), t2.set(this, r8)), (r8 = n2(this, r8.get(s10) || (r8.set(s10, r8 = function(n11) {
      for (var t14, s11, r9 = 1, e19 = "", u9 = "", h9 = [0], p9 = function(n12) {
        1 === r9 && (n12 || (e19 = e19.replace(/^\s*\n\s*|\s*\n\s*$/g, ""))) ? h9.push(0, n12, e19) : 3 === r9 && (n12 || e19) ? (h9.push(3, n12, e19), r9 = 2) : 2 === r9 && "..." === e19 && n12 ? h9.push(4, n12, 0) : 2 === r9 && e19 && !n12 ? h9.push(5, 0, true, e19) : r9 >= 5 && ((e19 || !n12 && 5 === r9) && (h9.push(r9, 0, e19, s11), r9 = 6), n12 && (h9.push(r9, n12, 0, s11), r9 = 6)), e19 = "";
      }, a8 = 0; a8 < n11.length; a8++) {
        a8 && (1 === r9 && p9(), p9(a8));
        for (var l10 = 0; l10 < n11[a8].length; l10++)
          t14 = n11[a8][l10], 1 === r9 ? "<" === t14 ? (p9(), h9 = [h9], r9 = 3) : e19 += t14 : 4 === r9 ? "--" === e19 && ">" === t14 ? (r9 = 1, e19 = "") : e19 = t14 + e19[0] : u9 ? t14 === u9 ? u9 = "" : e19 += t14 : '"' === t14 || "'" === t14 ? u9 = t14 : ">" === t14 ? (p9(), r9 = 1) : r9 && ("=" === t14 ? (r9 = 5, s11 = e19, e19 = "") : "/" === t14 && (r9 < 5 || ">" === n11[a8][l10 + 1]) ? (p9(), 3 === r9 && (h9 = h9[0]), r9 = h9, (h9 = h9[0]).push(2, 0, r9), r9 = 0) : " " === t14 || "	" === t14 || "\n" === t14 || "\r" === t14 ? (p9(), r9 = 2) : e19 += t14), 3 === r9 && "!--" === e19 && (r9 = 4, h9 = h9[0]);
      }
      return p9(), h9;
    }(s10)), r8), arguments, [])).length > 1 ? r8 : r8[0];
  }

  // http-url:https://unpkg.com/htm/preact/index.module.js?module
  var m2 = htm_latest_module_default.bind(y);

  // http-url:https://cdn.jsdelivr.net/npm/lodash@4.17.21/debounce/+esm
  var t3 = "undefined" != typeof globalThis ? globalThis : "undefined" != typeof window ? window : "undefined" != typeof global ? global : "undefined" != typeof self ? self : {};
  var n3 = function(t14) {
    var n11 = typeof t14;
    return null != t14 && ("object" == n11 || "function" == n11);
  };
  var e2 = "object" == typeof t3 && t3 && t3.Object === Object && t3;
  var r2 = "object" == typeof self && self && self.Object === Object && self;
  var o2 = e2 || r2 || Function("return this")();
  var i2 = o2;
  var u2 = function() {
    return i2.Date.now();
  };
  var f2 = /\s/;
  var a2 = function(t14) {
    for (var n11 = t14.length; n11-- && f2.test(t14.charAt(n11)); )
      ;
    return n11;
  };
  var c2 = /^\s+/;
  var l2 = function(t14) {
    return t14 ? t14.slice(0, a2(t14) + 1).replace(c2, "") : t14;
  };
  var v2 = o2.Symbol;
  var d2 = v2;
  var s2 = Object.prototype;
  var p2 = s2.hasOwnProperty;
  var b2 = s2.toString;
  var y2 = d2 ? d2.toStringTag : void 0;
  var g2 = function(t14) {
    var n11 = p2.call(t14, y2), e19 = t14[y2];
    try {
      t14[y2] = void 0;
      var r8 = true;
    } catch (t15) {
    }
    var o11 = b2.call(t14);
    return r8 && (n11 ? t14[y2] = e19 : delete t14[y2]), o11;
  };
  var j2 = Object.prototype.toString;
  var m3 = g2;
  var h2 = function(t14) {
    return j2.call(t14);
  };
  var T2 = v2 ? v2.toStringTag : void 0;
  var O2 = function(t14) {
    return null == t14 ? void 0 === t14 ? "[object Undefined]" : "[object Null]" : T2 && T2 in Object(t14) ? m3(t14) : h2(t14);
  };
  var w2 = function(t14) {
    return null != t14 && "object" == typeof t14;
  };
  var x2 = l2;
  var S2 = n3;
  var N2 = function(t14) {
    return "symbol" == typeof t14 || w2(t14) && "[object Symbol]" == O2(t14);
  };
  var $ = /^[-+]0x[0-9a-f]+$/i;
  var E = /^0b[01]+$/i;
  var M2 = /^0o[0-7]+$/i;
  var W = parseInt;
  var A2 = n3;
  var D2 = u2;
  var F = function(t14) {
    if ("number" == typeof t14)
      return t14;
    if (N2(t14))
      return NaN;
    if (S2(t14)) {
      var n11 = "function" == typeof t14.valueOf ? t14.valueOf() : t14;
      t14 = S2(n11) ? n11 + "" : n11;
    }
    if ("string" != typeof t14)
      return 0 === t14 ? t14 : +t14;
    t14 = x2(t14);
    var e19 = E.test(t14);
    return e19 || M2.test(t14) ? W(t14.slice(2), e19 ? 2 : 8) : $.test(t14) ? NaN : +t14;
  };
  var I2 = Math.max;
  var P2 = Math.min;
  var U = function(t14, n11, e19) {
    var r8, o11, i9, u9, f10, a8, c9 = 0, l10 = false, v11 = false, d10 = true;
    if ("function" != typeof t14)
      throw new TypeError("Expected a function");
    function s10(n12) {
      var e20 = r8, i10 = o11;
      return r8 = o11 = void 0, c9 = n12, u9 = t14.apply(i10, e20);
    }
    function p9(t15) {
      var e20 = t15 - a8;
      return void 0 === a8 || e20 >= n11 || e20 < 0 || v11 && t15 - c9 >= i9;
    }
    function b10() {
      var t15 = D2();
      if (p9(t15))
        return y9(t15);
      f10 = setTimeout(b10, function(t16) {
        var e20 = n11 - (t16 - a8);
        return v11 ? P2(e20, i9 - (t16 - c9)) : e20;
      }(t15));
    }
    function y9(t15) {
      return f10 = void 0, d10 && r8 ? s10(t15) : (r8 = o11 = void 0, u9);
    }
    function g8() {
      var t15 = D2(), e20 = p9(t15);
      if (r8 = arguments, o11 = this, a8 = t15, e20) {
        if (void 0 === f10)
          return function(t16) {
            return c9 = t16, f10 = setTimeout(b10, n11), l10 ? s10(t16) : u9;
          }(a8);
        if (v11)
          return clearTimeout(f10), f10 = setTimeout(b10, n11), s10(a8);
      }
      return void 0 === f10 && (f10 = setTimeout(b10, n11)), u9;
    }
    return n11 = F(n11) || 0, A2(e19) && (l10 = !!e19.leading, i9 = (v11 = "maxWait" in e19) ? I2(F(e19.maxWait) || 0, n11) : i9, d10 = "trailing" in e19 ? !!e19.trailing : d10), g8.cancel = function() {
      void 0 !== f10 && clearTimeout(f10), c9 = 0, r8 = a8 = o11 = f10 = void 0;
    }, g8.flush = function() {
      return void 0 === f10 ? u9 : y9(D2());
    }, g8;
  };

  // http-url:https://cdn.jsdelivr.net/npm/heap@0.2.7/+esm
  var t4;
  var n4 = "undefined" != typeof globalThis ? globalThis : "undefined" != typeof window ? window : "undefined" != typeof global ? global : "undefined" != typeof self ? self : {};
  var e3 = { exports: {} };
  t4 = e3, function() {
    var n11, e19, o11, r8, p9, u9, i9, l10, s10, f10, h9, c9, a8, y9, d10;
    o11 = Math.floor, f10 = Math.min, e19 = function(t14, n12) {
      return t14 < n12 ? -1 : t14 > n12 ? 1 : 0;
    }, s10 = function(t14, n12, r9, p10, u10) {
      var i10;
      if (null == r9 && (r9 = 0), null == u10 && (u10 = e19), r9 < 0)
        throw new Error("lo must be non-negative");
      for (null == p10 && (p10 = t14.length); r9 < p10; )
        u10(n12, t14[i10 = o11((r9 + p10) / 2)]) < 0 ? p10 = i10 : r9 = i10 + 1;
      return [].splice.apply(t14, [r9, r9 - r9].concat(n12)), n12;
    }, u9 = function(t14, n12, o12) {
      return null == o12 && (o12 = e19), t14.push(n12), y9(t14, 0, t14.length - 1, o12);
    }, p9 = function(t14, n12) {
      var o12, r9;
      return null == n12 && (n12 = e19), o12 = t14.pop(), t14.length ? (r9 = t14[0], t14[0] = o12, d10(t14, 0, n12)) : r9 = o12, r9;
    }, l10 = function(t14, n12, o12) {
      var r9;
      return null == o12 && (o12 = e19), r9 = t14[0], t14[0] = n12, d10(t14, 0, o12), r9;
    }, i9 = function(t14, n12, o12) {
      var r9;
      return null == o12 && (o12 = e19), t14.length && o12(t14[0], n12) < 0 && (n12 = (r9 = [t14[0], n12])[0], t14[0] = r9[1], d10(t14, 0, o12)), n12;
    }, r8 = function(t14, n12) {
      var r9, p10, u10, i10, l11, s11;
      for (null == n12 && (n12 = e19), l11 = [], p10 = 0, u10 = (i10 = function() {
        s11 = [];
        for (var n13 = 0, e20 = o11(t14.length / 2); 0 <= e20 ? n13 < e20 : n13 > e20; 0 <= e20 ? n13++ : n13--)
          s11.push(n13);
        return s11;
      }.apply(this).reverse()).length; p10 < u10; p10++)
        r9 = i10[p10], l11.push(d10(t14, r9, n12));
      return l11;
    }, a8 = function(t14, n12, o12) {
      var r9;
      if (null == o12 && (o12 = e19), -1 !== (r9 = t14.indexOf(n12)))
        return y9(t14, 0, r9, o12), d10(t14, r9, o12);
    }, h9 = function(t14, n12, o12) {
      var p10, u10, l11, s11, f11;
      if (null == o12 && (o12 = e19), !(u10 = t14.slice(0, n12)).length)
        return u10;
      for (r8(u10, o12), l11 = 0, s11 = (f11 = t14.slice(n12)).length; l11 < s11; l11++)
        p10 = f11[l11], i9(u10, p10, o12);
      return u10.sort(o12).reverse();
    }, c9 = function(t14, n12, o12) {
      var u10, i10, l11, h10, c10, a9, y10, d11, g8;
      if (null == o12 && (o12 = e19), 10 * n12 <= t14.length) {
        if (!(l11 = t14.slice(0, n12).sort(o12)).length)
          return l11;
        for (i10 = l11[l11.length - 1], h10 = 0, a9 = (y10 = t14.slice(n12)).length; h10 < a9; h10++)
          o12(u10 = y10[h10], i10) < 0 && (s10(l11, u10, 0, null, o12), l11.pop(), i10 = l11[l11.length - 1]);
        return l11;
      }
      for (r8(t14, o12), g8 = [], c10 = 0, d11 = f10(n12, t14.length); 0 <= d11 ? c10 < d11 : c10 > d11; 0 <= d11 ? ++c10 : --c10)
        g8.push(p9(t14, o12));
      return g8;
    }, y9 = function(t14, n12, o12, r9) {
      var p10, u10, i10;
      for (null == r9 && (r9 = e19), p10 = t14[o12]; o12 > n12 && r9(p10, u10 = t14[i10 = o12 - 1 >> 1]) < 0; )
        t14[o12] = u10, o12 = i10;
      return t14[o12] = p10;
    }, d10 = function(t14, n12, o12) {
      var r9, p10, u10, i10, l11;
      for (null == o12 && (o12 = e19), p10 = t14.length, l11 = n12, u10 = t14[n12], r9 = 2 * n12 + 1; r9 < p10; )
        (i10 = r9 + 1) < p10 && !(o12(t14[r9], t14[i10]) < 0) && (r9 = i10), t14[n12] = t14[r9], r9 = 2 * (n12 = r9) + 1;
      return t14[n12] = u10, y9(t14, l11, n12, o12);
    }, n11 = function() {
      function t14(t15) {
        this.cmp = null != t15 ? t15 : e19, this.nodes = [];
      }
      return t14.push = u9, t14.pop = p9, t14.replace = l10, t14.pushpop = i9, t14.heapify = r8, t14.updateItem = a8, t14.nlargest = h9, t14.nsmallest = c9, t14.prototype.push = function(t15) {
        return u9(this.nodes, t15, this.cmp);
      }, t14.prototype.pop = function() {
        return p9(this.nodes, this.cmp);
      }, t14.prototype.peek = function() {
        return this.nodes[0];
      }, t14.prototype.contains = function(t15) {
        return -1 !== this.nodes.indexOf(t15);
      }, t14.prototype.replace = function(t15) {
        return l10(this.nodes, t15, this.cmp);
      }, t14.prototype.pushpop = function(t15) {
        return i9(this.nodes, t15, this.cmp);
      }, t14.prototype.heapify = function() {
        return r8(this.nodes, this.cmp);
      }, t14.prototype.updateItem = function(t15) {
        return a8(this.nodes, t15, this.cmp);
      }, t14.prototype.clear = function() {
        return this.nodes = [];
      }, t14.prototype.empty = function() {
        return 0 === this.nodes.length;
      }, t14.prototype.size = function() {
        return this.nodes.length;
      }, t14.prototype.clone = function() {
        var n12;
        return (n12 = new t14()).nodes = this.nodes.slice(0), n12;
      }, t14.prototype.toArray = function() {
        return this.nodes.slice(0);
      }, t14.prototype.insert = t14.prototype.push, t14.prototype.top = t14.prototype.peek, t14.prototype.front = t14.prototype.peek, t14.prototype.has = t14.prototype.contains, t14.prototype.copy = t14.prototype.clone, t14;
    }(), t4.exports = n11;
  }.call(n4);
  var o3 = e3.exports;

  // http-url:https://cdn.jsdelivr.net/npm/lodash@4.17.21/get/+esm
  var t5 = "undefined" != typeof globalThis ? globalThis : "undefined" != typeof window ? window : "undefined" != typeof global ? global : "undefined" != typeof self ? self : {};
  var r3 = Array.isArray;
  var n5 = "object" == typeof t5 && t5 && t5.Object === Object && t5;
  var e4 = "object" == typeof self && self && self.Object === Object && self;
  var o4 = n5 || e4 || Function("return this")();
  var a3 = o4.Symbol;
  var i3 = a3;
  var u3 = Object.prototype;
  var c3 = u3.hasOwnProperty;
  var s3 = u3.toString;
  var l3 = i3 ? i3.toStringTag : void 0;
  var f3 = function(t14) {
    var r8 = c3.call(t14, l3), n11 = t14[l3];
    try {
      t14[l3] = void 0;
      var e19 = true;
    } catch (t15) {
    }
    var o11 = s3.call(t14);
    return e19 && (r8 ? t14[l3] = n11 : delete t14[l3]), o11;
  };
  var v3 = Object.prototype.toString;
  var p3 = f3;
  var h3 = function(t14) {
    return v3.call(t14);
  };
  var _2 = a3 ? a3.toStringTag : void 0;
  var y3 = function(t14) {
    return null == t14 ? void 0 === t14 ? "[object Undefined]" : "[object Null]" : _2 && _2 in Object(t14) ? p3(t14) : h3(t14);
  };
  var d3 = y3;
  var b3 = function(t14) {
    return null != t14 && "object" == typeof t14;
  };
  var g3 = function(t14) {
    return "symbol" == typeof t14 || b3(t14) && "[object Symbol]" == d3(t14);
  };
  var j3 = r3;
  var O3 = g3;
  var w3 = /\.|\[(?:[^[\]]*|(["'])(?:(?!\1)[^\\]|\\.)*?\1)\]/;
  var z2 = /^\w*$/;
  var m4 = function(t14, r8) {
    if (j3(t14))
      return false;
    var n11 = typeof t14;
    return !("number" != n11 && "symbol" != n11 && "boolean" != n11 && null != t14 && !O3(t14)) || (z2.test(t14) || !w3.test(t14) || null != r8 && t14 in Object(r8));
  };
  var S3 = function(t14) {
    var r8 = typeof t14;
    return null != t14 && ("object" == r8 || "function" == r8);
  };
  var $2 = y3;
  var P3 = S3;
  var A3;
  var F2 = function(t14) {
    if (!P3(t14))
      return false;
    var r8 = $2(t14);
    return "[object Function]" == r8 || "[object GeneratorFunction]" == r8 || "[object AsyncFunction]" == r8 || "[object Proxy]" == r8;
  };
  var T3 = o4["__core-js_shared__"];
  var x3 = (A3 = /[^.]+$/.exec(T3 && T3.keys && T3.keys.IE_PROTO || "")) ? "Symbol(src)_1." + A3 : "";
  var C2 = function(t14) {
    return !!x3 && x3 in t14;
  };
  var E2 = Function.prototype.toString;
  var I3 = F2;
  var k2 = C2;
  var R = S3;
  var G = function(t14) {
    if (null != t14) {
      try {
        return E2.call(t14);
      } catch (t15) {
      }
      try {
        return t14 + "";
      } catch (t15) {
      }
    }
    return "";
  };
  var M3 = /^\[object .+?Constructor\]$/;
  var N3 = Function.prototype;
  var U2 = Object.prototype;
  var q2 = N3.toString;
  var B2 = U2.hasOwnProperty;
  var D3 = RegExp("^" + q2.call(B2).replace(/[\\^$.*+?()[\]{}|]/g, "\\$&").replace(/hasOwnProperty|(function).*?(?=\\\()| for .+?(?=\\\])/g, "$1.*?") + "$");
  var H2 = function(t14) {
    return !(!R(t14) || k2(t14)) && (I3(t14) ? D3 : M3).test(G(t14));
  };
  var J = function(t14, r8) {
    return null == t14 ? void 0 : t14[r8];
  };
  var K = function(t14, r8) {
    var n11 = J(t14, r8);
    return H2(n11) ? n11 : void 0;
  };
  var L2 = K(Object, "create");
  var Q = L2;
  var V = function() {
    this.__data__ = Q ? Q(null) : {}, this.size = 0;
  };
  var W2 = function(t14) {
    var r8 = this.has(t14) && delete this.__data__[t14];
    return this.size -= r8 ? 1 : 0, r8;
  };
  var X = L2;
  var Y = Object.prototype.hasOwnProperty;
  var Z = function(t14) {
    var r8 = this.__data__;
    if (X) {
      var n11 = r8[t14];
      return "__lodash_hash_undefined__" === n11 ? void 0 : n11;
    }
    return Y.call(r8, t14) ? r8[t14] : void 0;
  };
  var tt = L2;
  var rt = Object.prototype.hasOwnProperty;
  var nt = L2;
  var et = V;
  var ot = W2;
  var at = Z;
  var it = function(t14) {
    var r8 = this.__data__;
    return tt ? void 0 !== r8[t14] : rt.call(r8, t14);
  };
  var ut = function(t14, r8) {
    var n11 = this.__data__;
    return this.size += this.has(t14) ? 0 : 1, n11[t14] = nt && void 0 === r8 ? "__lodash_hash_undefined__" : r8, this;
  };
  function ct(t14) {
    var r8 = -1, n11 = null == t14 ? 0 : t14.length;
    for (this.clear(); ++r8 < n11; ) {
      var e19 = t14[r8];
      this.set(e19[0], e19[1]);
    }
  }
  ct.prototype.clear = et, ct.prototype.delete = ot, ct.prototype.get = at, ct.prototype.has = it, ct.prototype.set = ut;
  var st = ct;
  var lt = function() {
    this.__data__ = [], this.size = 0;
  };
  var ft = function(t14, r8) {
    return t14 === r8 || t14 != t14 && r8 != r8;
  };
  var vt = function(t14, r8) {
    for (var n11 = t14.length; n11--; )
      if (ft(t14[n11][0], r8))
        return n11;
    return -1;
  };
  var pt = vt;
  var ht = Array.prototype.splice;
  var _t = vt;
  var yt = vt;
  var dt = vt;
  var bt = lt;
  var gt = function(t14) {
    var r8 = this.__data__, n11 = pt(r8, t14);
    return !(n11 < 0) && (n11 == r8.length - 1 ? r8.pop() : ht.call(r8, n11, 1), --this.size, true);
  };
  var jt = function(t14) {
    var r8 = this.__data__, n11 = _t(r8, t14);
    return n11 < 0 ? void 0 : r8[n11][1];
  };
  var Ot = function(t14) {
    return yt(this.__data__, t14) > -1;
  };
  var wt = function(t14, r8) {
    var n11 = this.__data__, e19 = dt(n11, t14);
    return e19 < 0 ? (++this.size, n11.push([t14, r8])) : n11[e19][1] = r8, this;
  };
  function zt(t14) {
    var r8 = -1, n11 = null == t14 ? 0 : t14.length;
    for (this.clear(); ++r8 < n11; ) {
      var e19 = t14[r8];
      this.set(e19[0], e19[1]);
    }
  }
  zt.prototype.clear = bt, zt.prototype.delete = gt, zt.prototype.get = jt, zt.prototype.has = Ot, zt.prototype.set = wt;
  var mt = zt;
  var St = K(o4, "Map");
  var $t = st;
  var Pt = mt;
  var At = St;
  var Ft = function(t14) {
    var r8 = typeof t14;
    return "string" == r8 || "number" == r8 || "symbol" == r8 || "boolean" == r8 ? "__proto__" !== t14 : null === t14;
  };
  var Tt = function(t14, r8) {
    var n11 = t14.__data__;
    return Ft(r8) ? n11["string" == typeof r8 ? "string" : "hash"] : n11.map;
  };
  var xt = Tt;
  var Ct = Tt;
  var Et = Tt;
  var It = Tt;
  var kt = function() {
    this.size = 0, this.__data__ = { hash: new $t(), map: new (At || Pt)(), string: new $t() };
  };
  var Rt = function(t14) {
    var r8 = xt(this, t14).delete(t14);
    return this.size -= r8 ? 1 : 0, r8;
  };
  var Gt = function(t14) {
    return Ct(this, t14).get(t14);
  };
  var Mt = function(t14) {
    return Et(this, t14).has(t14);
  };
  var Nt = function(t14, r8) {
    var n11 = It(this, t14), e19 = n11.size;
    return n11.set(t14, r8), this.size += n11.size == e19 ? 0 : 1, this;
  };
  function Ut(t14) {
    var r8 = -1, n11 = null == t14 ? 0 : t14.length;
    for (this.clear(); ++r8 < n11; ) {
      var e19 = t14[r8];
      this.set(e19[0], e19[1]);
    }
  }
  Ut.prototype.clear = kt, Ut.prototype.delete = Rt, Ut.prototype.get = Gt, Ut.prototype.has = Mt, Ut.prototype.set = Nt;
  var qt = Ut;
  function Bt(t14, r8) {
    if ("function" != typeof t14 || null != r8 && "function" != typeof r8)
      throw new TypeError("Expected a function");
    var n11 = function() {
      var e19 = arguments, o11 = r8 ? r8.apply(this, e19) : e19[0], a8 = n11.cache;
      if (a8.has(o11))
        return a8.get(o11);
      var i9 = t14.apply(this, e19);
      return n11.cache = a8.set(o11, i9) || a8, i9;
    };
    return n11.cache = new (Bt.Cache || qt)(), n11;
  }
  Bt.Cache = qt;
  var Dt = Bt;
  var Ht = /[^.[\]]+|\[(?:(-?\d+(?:\.\d+)?)|(["'])((?:(?!\2)[^\\]|\\.)*?)\2)\]|(?=(?:\.|\[\])(?:\.|\[\]|$))/g;
  var Jt = /\\(\\)?/g;
  var Kt = function(t14) {
    var r8 = Dt(t14, function(t15) {
      return 500 === n11.size && n11.clear(), t15;
    }), n11 = r8.cache;
    return r8;
  }(function(t14) {
    var r8 = [];
    return 46 === t14.charCodeAt(0) && r8.push(""), t14.replace(Ht, function(t15, n11, e19, o11) {
      r8.push(e19 ? o11.replace(Jt, "$1") : n11 || t15);
    }), r8;
  });
  var Lt = function(t14, r8) {
    for (var n11 = -1, e19 = null == t14 ? 0 : t14.length, o11 = Array(e19); ++n11 < e19; )
      o11[n11] = r8(t14[n11], n11, t14);
    return o11;
  };
  var Qt = r3;
  var Vt = g3;
  var Wt = a3 ? a3.prototype : void 0;
  var Xt = Wt ? Wt.toString : void 0;
  var Yt = function t6(r8) {
    if ("string" == typeof r8)
      return r8;
    if (Qt(r8))
      return Lt(r8, t6) + "";
    if (Vt(r8))
      return Xt ? Xt.call(r8) : "";
    var n11 = r8 + "";
    return "0" == n11 && 1 / r8 == -Infinity ? "-0" : n11;
  };
  var Zt = Yt;
  var tr = r3;
  var rr = m4;
  var nr = Kt;
  var er = function(t14) {
    return null == t14 ? "" : Zt(t14);
  };
  var or = g3;
  var ar = function(t14, r8) {
    return tr(t14) ? t14 : rr(t14, r8) ? [t14] : nr(er(t14));
  };
  var ir = function(t14) {
    if ("string" == typeof t14 || or(t14))
      return t14;
    var r8 = t14 + "";
    return "0" == r8 && 1 / t14 == -Infinity ? "-0" : r8;
  };
  var ur = function(t14, r8) {
    for (var n11 = 0, e19 = (r8 = ar(r8, t14)).length; null != t14 && n11 < e19; )
      t14 = t14[ir(r8[n11++])];
    return n11 && n11 == e19 ? t14 : void 0;
  };
  var cr = function(t14, r8, n11) {
    var e19 = null == t14 ? void 0 : ur(t14, r8);
    return void 0 === e19 ? n11 : e19;
  };

  // http-url:https://cdn.jsdelivr.net/npm/lodash@4.17.21/set/+esm
  var t7 = "undefined" != typeof globalThis ? globalThis : "undefined" != typeof window ? window : "undefined" != typeof global ? global : "undefined" != typeof self ? self : {};
  var r4 = "object" == typeof t7 && t7 && t7.Object === Object && t7;
  var n6 = "object" == typeof self && self && self.Object === Object && self;
  var e5 = r4 || n6 || Function("return this")();
  var o5 = e5.Symbol;
  var a4 = o5;
  var i4 = Object.prototype;
  var u4 = i4.hasOwnProperty;
  var c4 = i4.toString;
  var l4 = a4 ? a4.toStringTag : void 0;
  var f4 = function(t14) {
    var r8 = u4.call(t14, l4), n11 = t14[l4];
    try {
      t14[l4] = void 0;
      var e19 = true;
    } catch (t15) {
    }
    var o11 = c4.call(t14);
    return e19 && (r8 ? t14[l4] = n11 : delete t14[l4]), o11;
  };
  var s4 = Object.prototype.toString;
  var v4 = f4;
  var p4 = function(t14) {
    return s4.call(t14);
  };
  var h4 = o5 ? o5.toStringTag : void 0;
  var _3 = function(t14) {
    return null == t14 ? void 0 === t14 ? "[object Undefined]" : "[object Null]" : h4 && h4 in Object(t14) ? v4(t14) : p4(t14);
  };
  var y4 = function(t14) {
    var r8 = typeof t14;
    return null != t14 && ("object" == r8 || "function" == r8);
  };
  var d4 = _3;
  var b4 = y4;
  var g4;
  var j4 = function(t14) {
    if (!b4(t14))
      return false;
    var r8 = d4(t14);
    return "[object Function]" == r8 || "[object GeneratorFunction]" == r8 || "[object AsyncFunction]" == r8 || "[object Proxy]" == r8;
  };
  var O4 = e5["__core-js_shared__"];
  var w4 = (g4 = /[^.]+$/.exec(O4 && O4.keys && O4.keys.IE_PROTO || "")) ? "Symbol(src)_1." + g4 : "";
  var m5 = function(t14) {
    return !!w4 && w4 in t14;
  };
  var z3 = Function.prototype.toString;
  var S4 = j4;
  var $3 = m5;
  var P4 = y4;
  var A4 = function(t14) {
    if (null != t14) {
      try {
        return z3.call(t14);
      } catch (t15) {
      }
      try {
        return t14 + "";
      } catch (t15) {
      }
    }
    return "";
  };
  var F3 = /^\[object .+?Constructor\]$/;
  var T4 = Function.prototype;
  var x4 = Object.prototype;
  var C3 = T4.toString;
  var E3 = x4.hasOwnProperty;
  var I4 = RegExp("^" + C3.call(E3).replace(/[\\^$.*+?()[\]{}|]/g, "\\$&").replace(/hasOwnProperty|(function).*?(?=\\\()| for .+?(?=\\\])/g, "$1.*?") + "$");
  var k3 = function(t14) {
    return !(!P4(t14) || $3(t14)) && (S4(t14) ? I4 : F3).test(A4(t14));
  };
  var R2 = function(t14, r8) {
    return null == t14 ? void 0 : t14[r8];
  };
  var G2 = function(t14, r8) {
    var n11 = R2(t14, r8);
    return k3(n11) ? n11 : void 0;
  };
  var M4 = G2;
  var N4 = function() {
    try {
      var t14 = M4(Object, "defineProperty");
      return t14({}, "", {}), t14;
    } catch (t15) {
    }
  }();
  var U3 = function(t14, r8) {
    return t14 === r8 || t14 != t14 && r8 != r8;
  };
  var q3 = function(t14, r8, n11) {
    "__proto__" == r8 && N4 ? N4(t14, r8, { configurable: true, enumerable: true, value: n11, writable: true }) : t14[r8] = n11;
  };
  var B3 = U3;
  var D4 = Object.prototype.hasOwnProperty;
  var H3 = function(t14, r8, n11) {
    var e19 = t14[r8];
    D4.call(t14, r8) && B3(e19, n11) && (void 0 !== n11 || r8 in t14) || q3(t14, r8, n11);
  };
  var J2 = Array.isArray;
  var K2 = _3;
  var L3 = function(t14) {
    return null != t14 && "object" == typeof t14;
  };
  var Q2 = function(t14) {
    return "symbol" == typeof t14 || L3(t14) && "[object Symbol]" == K2(t14);
  };
  var V2 = J2;
  var W3 = Q2;
  var X2 = /\.|\[(?:[^[\]]*|(["'])(?:(?!\1)[^\\]|\\.)*?\1)\]/;
  var Y2 = /^\w*$/;
  var Z2 = function(t14, r8) {
    if (V2(t14))
      return false;
    var n11 = typeof t14;
    return !("number" != n11 && "symbol" != n11 && "boolean" != n11 && null != t14 && !W3(t14)) || (Y2.test(t14) || !X2.test(t14) || null != r8 && t14 in Object(r8));
  };
  var tt2 = G2(Object, "create");
  var rt2 = tt2;
  var nt2 = function() {
    this.__data__ = rt2 ? rt2(null) : {}, this.size = 0;
  };
  var et2 = function(t14) {
    var r8 = this.has(t14) && delete this.__data__[t14];
    return this.size -= r8 ? 1 : 0, r8;
  };
  var ot2 = tt2;
  var at2 = Object.prototype.hasOwnProperty;
  var it2 = function(t14) {
    var r8 = this.__data__;
    if (ot2) {
      var n11 = r8[t14];
      return "__lodash_hash_undefined__" === n11 ? void 0 : n11;
    }
    return at2.call(r8, t14) ? r8[t14] : void 0;
  };
  var ut2 = tt2;
  var ct2 = Object.prototype.hasOwnProperty;
  var lt2 = tt2;
  var ft2 = nt2;
  var st2 = et2;
  var vt2 = it2;
  var pt2 = function(t14) {
    var r8 = this.__data__;
    return ut2 ? void 0 !== r8[t14] : ct2.call(r8, t14);
  };
  var ht2 = function(t14, r8) {
    var n11 = this.__data__;
    return this.size += this.has(t14) ? 0 : 1, n11[t14] = lt2 && void 0 === r8 ? "__lodash_hash_undefined__" : r8, this;
  };
  function _t2(t14) {
    var r8 = -1, n11 = null == t14 ? 0 : t14.length;
    for (this.clear(); ++r8 < n11; ) {
      var e19 = t14[r8];
      this.set(e19[0], e19[1]);
    }
  }
  _t2.prototype.clear = ft2, _t2.prototype.delete = st2, _t2.prototype.get = vt2, _t2.prototype.has = pt2, _t2.prototype.set = ht2;
  var yt2 = _t2;
  var dt2 = function() {
    this.__data__ = [], this.size = 0;
  };
  var bt2 = U3;
  var gt2 = function(t14, r8) {
    for (var n11 = t14.length; n11--; )
      if (bt2(t14[n11][0], r8))
        return n11;
    return -1;
  };
  var jt2 = gt2;
  var Ot2 = Array.prototype.splice;
  var wt2 = gt2;
  var mt2 = gt2;
  var zt2 = gt2;
  var St2 = dt2;
  var $t2 = function(t14) {
    var r8 = this.__data__, n11 = jt2(r8, t14);
    return !(n11 < 0) && (n11 == r8.length - 1 ? r8.pop() : Ot2.call(r8, n11, 1), --this.size, true);
  };
  var Pt2 = function(t14) {
    var r8 = this.__data__, n11 = wt2(r8, t14);
    return n11 < 0 ? void 0 : r8[n11][1];
  };
  var At2 = function(t14) {
    return mt2(this.__data__, t14) > -1;
  };
  var Ft2 = function(t14, r8) {
    var n11 = this.__data__, e19 = zt2(n11, t14);
    return e19 < 0 ? (++this.size, n11.push([t14, r8])) : n11[e19][1] = r8, this;
  };
  function Tt2(t14) {
    var r8 = -1, n11 = null == t14 ? 0 : t14.length;
    for (this.clear(); ++r8 < n11; ) {
      var e19 = t14[r8];
      this.set(e19[0], e19[1]);
    }
  }
  Tt2.prototype.clear = St2, Tt2.prototype.delete = $t2, Tt2.prototype.get = Pt2, Tt2.prototype.has = At2, Tt2.prototype.set = Ft2;
  var xt2 = Tt2;
  var Ct2 = G2(e5, "Map");
  var Et2 = yt2;
  var It2 = xt2;
  var kt2 = Ct2;
  var Rt2 = function(t14) {
    var r8 = typeof t14;
    return "string" == r8 || "number" == r8 || "symbol" == r8 || "boolean" == r8 ? "__proto__" !== t14 : null === t14;
  };
  var Gt2 = function(t14, r8) {
    var n11 = t14.__data__;
    return Rt2(r8) ? n11["string" == typeof r8 ? "string" : "hash"] : n11.map;
  };
  var Mt2 = Gt2;
  var Nt2 = Gt2;
  var Ut2 = Gt2;
  var qt2 = Gt2;
  var Bt2 = function() {
    this.size = 0, this.__data__ = { hash: new Et2(), map: new (kt2 || It2)(), string: new Et2() };
  };
  var Dt2 = function(t14) {
    var r8 = Mt2(this, t14).delete(t14);
    return this.size -= r8 ? 1 : 0, r8;
  };
  var Ht2 = function(t14) {
    return Nt2(this, t14).get(t14);
  };
  var Jt2 = function(t14) {
    return Ut2(this, t14).has(t14);
  };
  var Kt2 = function(t14, r8) {
    var n11 = qt2(this, t14), e19 = n11.size;
    return n11.set(t14, r8), this.size += n11.size == e19 ? 0 : 1, this;
  };
  function Lt2(t14) {
    var r8 = -1, n11 = null == t14 ? 0 : t14.length;
    for (this.clear(); ++r8 < n11; ) {
      var e19 = t14[r8];
      this.set(e19[0], e19[1]);
    }
  }
  Lt2.prototype.clear = Bt2, Lt2.prototype.delete = Dt2, Lt2.prototype.get = Ht2, Lt2.prototype.has = Jt2, Lt2.prototype.set = Kt2;
  var Qt2 = Lt2;
  function Vt2(t14, r8) {
    if ("function" != typeof t14 || null != r8 && "function" != typeof r8)
      throw new TypeError("Expected a function");
    var n11 = function() {
      var e19 = arguments, o11 = r8 ? r8.apply(this, e19) : e19[0], a8 = n11.cache;
      if (a8.has(o11))
        return a8.get(o11);
      var i9 = t14.apply(this, e19);
      return n11.cache = a8.set(o11, i9) || a8, i9;
    };
    return n11.cache = new (Vt2.Cache || Qt2)(), n11;
  }
  Vt2.Cache = Qt2;
  var Wt2 = Vt2;
  var Xt2 = /[^.[\]]+|\[(?:(-?\d+(?:\.\d+)?)|(["'])((?:(?!\2)[^\\]|\\.)*?)\2)\]|(?=(?:\.|\[\])(?:\.|\[\]|$))/g;
  var Yt2 = /\\(\\)?/g;
  var Zt2 = function(t14) {
    var r8 = Wt2(t14, function(t15) {
      return 500 === n11.size && n11.clear(), t15;
    }), n11 = r8.cache;
    return r8;
  }(function(t14) {
    var r8 = [];
    return 46 === t14.charCodeAt(0) && r8.push(""), t14.replace(Xt2, function(t15, n11, e19, o11) {
      r8.push(e19 ? o11.replace(Yt2, "$1") : n11 || t15);
    }), r8;
  });
  var tr2 = function(t14, r8) {
    for (var n11 = -1, e19 = null == t14 ? 0 : t14.length, o11 = Array(e19); ++n11 < e19; )
      o11[n11] = r8(t14[n11], n11, t14);
    return o11;
  };
  var rr2 = J2;
  var nr2 = Q2;
  var er2 = o5 ? o5.prototype : void 0;
  var or2 = er2 ? er2.toString : void 0;
  var ar2 = function t8(r8) {
    if ("string" == typeof r8)
      return r8;
    if (rr2(r8))
      return tr2(r8, t8) + "";
    if (nr2(r8))
      return or2 ? or2.call(r8) : "";
    var n11 = r8 + "";
    return "0" == n11 && 1 / r8 == -Infinity ? "-0" : n11;
  };
  var ir2 = ar2;
  var ur2 = J2;
  var cr2 = Z2;
  var lr = Zt2;
  var fr = function(t14) {
    return null == t14 ? "" : ir2(t14);
  };
  var sr = /^(?:0|[1-9]\d*)$/;
  var vr = Q2;
  var pr = H3;
  var hr = function(t14, r8) {
    return ur2(t14) ? t14 : cr2(t14, r8) ? [t14] : lr(fr(t14));
  };
  var _r = function(t14, r8) {
    var n11 = typeof t14;
    return !!(r8 = null == r8 ? 9007199254740991 : r8) && ("number" == n11 || "symbol" != n11 && sr.test(t14)) && t14 > -1 && t14 % 1 == 0 && t14 < r8;
  };
  var yr = y4;
  var dr = function(t14) {
    if ("string" == typeof t14 || vr(t14))
      return t14;
    var r8 = t14 + "";
    return "0" == r8 && 1 / t14 == -Infinity ? "-0" : r8;
  };
  var br = function(t14, r8, n11, e19) {
    if (!yr(t14))
      return t14;
    for (var o11 = -1, a8 = (r8 = hr(r8, t14)).length, i9 = a8 - 1, u9 = t14; null != u9 && ++o11 < a8; ) {
      var c9 = dr(r8[o11]), l10 = n11;
      if ("__proto__" === c9 || "constructor" === c9 || "prototype" === c9)
        return t14;
      if (o11 != i9) {
        var f10 = u9[c9];
        void 0 === (l10 = e19 ? e19(f10, c9, u9) : void 0) && (l10 = yr(f10) ? f10 : _r(r8[o11 + 1]) ? [] : {});
      }
      pr(u9, c9, l10), u9 = u9[c9];
    }
    return t14;
  };
  var gr = function(t14, r8, n11) {
    return null == t14 ? t14 : br(t14, r8, n11);
  };

  // http-url:https://cdn.jsdelivr.net/npm/lodash@4.17.21/toPath/+esm
  var t9 = "undefined" != typeof globalThis ? globalThis : "undefined" != typeof window ? window : "undefined" != typeof global ? global : "undefined" != typeof self ? self : {};
  var r5 = function(t14, r8) {
    for (var e19 = -1, n11 = null == t14 ? 0 : t14.length, o11 = Array(n11); ++e19 < n11; )
      o11[e19] = r8(t14[e19], e19, t14);
    return o11;
  };
  var e6 = function(t14, r8) {
    var e19 = -1, n11 = t14.length;
    for (r8 || (r8 = Array(n11)); ++e19 < n11; )
      r8[e19] = t14[e19];
    return r8;
  };
  var n7 = Array.isArray;
  var o6 = "object" == typeof t9 && t9 && t9.Object === Object && t9;
  var a5 = "object" == typeof self && self && self.Object === Object && self;
  var i5 = o6 || a5 || Function("return this")();
  var u5 = i5.Symbol;
  var c5 = u5;
  var s5 = Object.prototype;
  var f5 = s5.hasOwnProperty;
  var l5 = s5.toString;
  var p5 = c5 ? c5.toStringTag : void 0;
  var v5 = function(t14) {
    var r8 = f5.call(t14, p5), e19 = t14[p5];
    try {
      t14[p5] = void 0;
      var n11 = true;
    } catch (t15) {
    }
    var o11 = l5.call(t14);
    return n11 && (r8 ? t14[p5] = e19 : delete t14[p5]), o11;
  };
  var h5 = Object.prototype.toString;
  var _4 = v5;
  var y5 = function(t14) {
    return h5.call(t14);
  };
  var d5 = u5 ? u5.toStringTag : void 0;
  var g5 = function(t14) {
    return null == t14 ? void 0 === t14 ? "[object Undefined]" : "[object Null]" : d5 && d5 in Object(t14) ? _4(t14) : y5(t14);
  };
  var b5 = g5;
  var j5 = function(t14) {
    return null != t14 && "object" == typeof t14;
  };
  var O5 = function(t14) {
    return "symbol" == typeof t14 || j5(t14) && "[object Symbol]" == b5(t14);
  };
  var w5 = function(t14) {
    var r8 = typeof t14;
    return null != t14 && ("object" == r8 || "function" == r8);
  };
  var z4 = g5;
  var S5 = w5;
  var m6;
  var $4 = function(t14) {
    if (!S5(t14))
      return false;
    var r8 = z4(t14);
    return "[object Function]" == r8 || "[object GeneratorFunction]" == r8 || "[object AsyncFunction]" == r8 || "[object Proxy]" == r8;
  };
  var A5 = i5["__core-js_shared__"];
  var P5 = (m6 = /[^.]+$/.exec(A5 && A5.keys && A5.keys.IE_PROTO || "")) ? "Symbol(src)_1." + m6 : "";
  var F4 = function(t14) {
    return !!P5 && P5 in t14;
  };
  var T5 = Function.prototype.toString;
  var x5 = $4;
  var C4 = F4;
  var E4 = w5;
  var I5 = function(t14) {
    if (null != t14) {
      try {
        return T5.call(t14);
      } catch (t15) {
      }
      try {
        return t14 + "";
      } catch (t15) {
      }
    }
    return "";
  };
  var k4 = /^\[object .+?Constructor\]$/;
  var R3 = Function.prototype;
  var G3 = Object.prototype;
  var M5 = R3.toString;
  var N5 = G3.hasOwnProperty;
  var U4 = RegExp("^" + M5.call(N5).replace(/[\\^$.*+?()[\]{}|]/g, "\\$&").replace(/hasOwnProperty|(function).*?(?=\\\()| for .+?(?=\\\])/g, "$1.*?") + "$");
  var q4 = function(t14) {
    return !(!E4(t14) || C4(t14)) && (x5(t14) ? U4 : k4).test(I5(t14));
  };
  var B4 = function(t14, r8) {
    return null == t14 ? void 0 : t14[r8];
  };
  var D5 = function(t14, r8) {
    var e19 = B4(t14, r8);
    return q4(e19) ? e19 : void 0;
  };
  var H4 = D5(Object, "create");
  var J3 = H4;
  var K3 = function() {
    this.__data__ = J3 ? J3(null) : {}, this.size = 0;
  };
  var L4 = function(t14) {
    var r8 = this.has(t14) && delete this.__data__[t14];
    return this.size -= r8 ? 1 : 0, r8;
  };
  var Q3 = H4;
  var V3 = Object.prototype.hasOwnProperty;
  var W4 = function(t14) {
    var r8 = this.__data__;
    if (Q3) {
      var e19 = r8[t14];
      return "__lodash_hash_undefined__" === e19 ? void 0 : e19;
    }
    return V3.call(r8, t14) ? r8[t14] : void 0;
  };
  var X3 = H4;
  var Y3 = Object.prototype.hasOwnProperty;
  var Z3 = H4;
  var tt3 = K3;
  var rt3 = L4;
  var et3 = W4;
  var nt3 = function(t14) {
    var r8 = this.__data__;
    return X3 ? void 0 !== r8[t14] : Y3.call(r8, t14);
  };
  var ot3 = function(t14, r8) {
    var e19 = this.__data__;
    return this.size += this.has(t14) ? 0 : 1, e19[t14] = Z3 && void 0 === r8 ? "__lodash_hash_undefined__" : r8, this;
  };
  function at3(t14) {
    var r8 = -1, e19 = null == t14 ? 0 : t14.length;
    for (this.clear(); ++r8 < e19; ) {
      var n11 = t14[r8];
      this.set(n11[0], n11[1]);
    }
  }
  at3.prototype.clear = tt3, at3.prototype.delete = rt3, at3.prototype.get = et3, at3.prototype.has = nt3, at3.prototype.set = ot3;
  var it3 = at3;
  var ut3 = function() {
    this.__data__ = [], this.size = 0;
  };
  var ct3 = function(t14, r8) {
    return t14 === r8 || t14 != t14 && r8 != r8;
  };
  var st3 = function(t14, r8) {
    for (var e19 = t14.length; e19--; )
      if (ct3(t14[e19][0], r8))
        return e19;
    return -1;
  };
  var ft3 = st3;
  var lt3 = Array.prototype.splice;
  var pt3 = st3;
  var vt3 = st3;
  var ht3 = st3;
  var _t3 = ut3;
  var yt3 = function(t14) {
    var r8 = this.__data__, e19 = ft3(r8, t14);
    return !(e19 < 0) && (e19 == r8.length - 1 ? r8.pop() : lt3.call(r8, e19, 1), --this.size, true);
  };
  var dt3 = function(t14) {
    var r8 = this.__data__, e19 = pt3(r8, t14);
    return e19 < 0 ? void 0 : r8[e19][1];
  };
  var gt3 = function(t14) {
    return vt3(this.__data__, t14) > -1;
  };
  var bt3 = function(t14, r8) {
    var e19 = this.__data__, n11 = ht3(e19, t14);
    return n11 < 0 ? (++this.size, e19.push([t14, r8])) : e19[n11][1] = r8, this;
  };
  function jt3(t14) {
    var r8 = -1, e19 = null == t14 ? 0 : t14.length;
    for (this.clear(); ++r8 < e19; ) {
      var n11 = t14[r8];
      this.set(n11[0], n11[1]);
    }
  }
  jt3.prototype.clear = _t3, jt3.prototype.delete = yt3, jt3.prototype.get = dt3, jt3.prototype.has = gt3, jt3.prototype.set = bt3;
  var Ot3 = jt3;
  var wt3 = D5(i5, "Map");
  var zt3 = it3;
  var St3 = Ot3;
  var mt3 = wt3;
  var $t3 = function(t14) {
    var r8 = typeof t14;
    return "string" == r8 || "number" == r8 || "symbol" == r8 || "boolean" == r8 ? "__proto__" !== t14 : null === t14;
  };
  var At3 = function(t14, r8) {
    var e19 = t14.__data__;
    return $t3(r8) ? e19["string" == typeof r8 ? "string" : "hash"] : e19.map;
  };
  var Pt3 = At3;
  var Ft3 = At3;
  var Tt3 = At3;
  var xt3 = At3;
  var Ct3 = function() {
    this.size = 0, this.__data__ = { hash: new zt3(), map: new (mt3 || St3)(), string: new zt3() };
  };
  var Et3 = function(t14) {
    var r8 = Pt3(this, t14).delete(t14);
    return this.size -= r8 ? 1 : 0, r8;
  };
  var It3 = function(t14) {
    return Ft3(this, t14).get(t14);
  };
  var kt3 = function(t14) {
    return Tt3(this, t14).has(t14);
  };
  var Rt3 = function(t14, r8) {
    var e19 = xt3(this, t14), n11 = e19.size;
    return e19.set(t14, r8), this.size += e19.size == n11 ? 0 : 1, this;
  };
  function Gt3(t14) {
    var r8 = -1, e19 = null == t14 ? 0 : t14.length;
    for (this.clear(); ++r8 < e19; ) {
      var n11 = t14[r8];
      this.set(n11[0], n11[1]);
    }
  }
  Gt3.prototype.clear = Ct3, Gt3.prototype.delete = Et3, Gt3.prototype.get = It3, Gt3.prototype.has = kt3, Gt3.prototype.set = Rt3;
  var Mt3 = Gt3;
  function Nt3(t14, r8) {
    if ("function" != typeof t14 || null != r8 && "function" != typeof r8)
      throw new TypeError("Expected a function");
    var e19 = function() {
      var n11 = arguments, o11 = r8 ? r8.apply(this, n11) : n11[0], a8 = e19.cache;
      if (a8.has(o11))
        return a8.get(o11);
      var i9 = t14.apply(this, n11);
      return e19.cache = a8.set(o11, i9) || a8, i9;
    };
    return e19.cache = new (Nt3.Cache || Mt3)(), e19;
  }
  Nt3.Cache = Mt3;
  var Ut3 = Nt3;
  var qt3 = /[^.[\]]+|\[(?:(-?\d+(?:\.\d+)?)|(["'])((?:(?!\2)[^\\]|\\.)*?)\2)\]|(?=(?:\.|\[\])(?:\.|\[\]|$))/g;
  var Bt3 = /\\(\\)?/g;
  var Dt3 = function(t14) {
    var r8 = Ut3(t14, function(t15) {
      return 500 === e19.size && e19.clear(), t15;
    }), e19 = r8.cache;
    return r8;
  }(function(t14) {
    var r8 = [];
    return 46 === t14.charCodeAt(0) && r8.push(""), t14.replace(qt3, function(t15, e19, n11, o11) {
      r8.push(n11 ? o11.replace(Bt3, "$1") : e19 || t15);
    }), r8;
  });
  var Ht3 = O5;
  var Jt3 = function(t14) {
    if ("string" == typeof t14 || Ht3(t14))
      return t14;
    var r8 = t14 + "";
    return "0" == r8 && 1 / t14 == -Infinity ? "-0" : r8;
  };
  var Kt3 = r5;
  var Lt3 = n7;
  var Qt3 = O5;
  var Vt3 = u5 ? u5.prototype : void 0;
  var Wt3 = Vt3 ? Vt3.toString : void 0;
  var Xt3 = function t10(r8) {
    if ("string" == typeof r8)
      return r8;
    if (Lt3(r8))
      return Kt3(r8, t10) + "";
    if (Qt3(r8))
      return Wt3 ? Wt3.call(r8) : "";
    var e19 = r8 + "";
    return "0" == e19 && 1 / r8 == -Infinity ? "-0" : e19;
  };
  var Yt3 = Xt3;
  var Zt3 = r5;
  var tr3 = e6;
  var rr3 = n7;
  var er3 = O5;
  var nr3 = Dt3;
  var or3 = Jt3;
  var ar3 = function(t14) {
    return null == t14 ? "" : Yt3(t14);
  };
  var ir3 = function(t14) {
    return rr3(t14) ? Zt3(t14, or3) : er3(t14) ? [t14] : tr3(nr3(ar3(t14)));
  };

  // http-url:https://cdn.jsdelivr.net/npm/cytoscape@3.26.0/+esm
  var i6 = o3;
  var o7 = cr;
  var s6 = gr;
  var l6 = ir3;
  function u6(e19) {
    return e19 && "object" == typeof e19 && "default" in e19 ? e19 : { default: e19 };
  }
  var c6 = u6(U);
  var d6 = u6(i6);
  var h6 = u6(o7);
  var p6 = u6(s6);
  var f6 = u6(l6);
  function g6(e19) {
    return g6 = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(e20) {
      return typeof e20;
    } : function(e20) {
      return e20 && "function" == typeof Symbol && e20.constructor === Symbol && e20 !== Symbol.prototype ? "symbol" : typeof e20;
    }, g6(e19);
  }
  function v6(e19, t14) {
    if (!(e19 instanceof t14))
      throw new TypeError("Cannot call a class as a function");
  }
  function y6(e19, t14) {
    for (var n11 = 0; n11 < t14.length; n11++) {
      var r8 = t14[n11];
      r8.enumerable = r8.enumerable || false, r8.configurable = true, "value" in r8 && (r8.writable = true), Object.defineProperty(e19, r8.key, r8);
    }
  }
  function m7(e19, t14, n11) {
    return t14 && y6(e19.prototype, t14), n11 && y6(e19, n11), Object.defineProperty(e19, "prototype", { writable: false }), e19;
  }
  function b6(e19, t14, n11) {
    return t14 in e19 ? Object.defineProperty(e19, t14, { value: n11, enumerable: true, configurable: true, writable: true }) : e19[t14] = n11, e19;
  }
  function x6(e19, t14) {
    return function(e20) {
      if (Array.isArray(e20))
        return e20;
    }(e19) || function(e20, t15) {
      var n11 = null == e20 ? null : "undefined" != typeof Symbol && e20[Symbol.iterator] || e20["@@iterator"];
      if (null == n11)
        return;
      var r8, a8, i9 = [], o11 = true, s10 = false;
      try {
        for (n11 = n11.call(e20); !(o11 = (r8 = n11.next()).done) && (i9.push(r8.value), !t15 || i9.length !== t15); o11 = true)
          ;
      } catch (e21) {
        s10 = true, a8 = e21;
      } finally {
        try {
          o11 || null == n11.return || n11.return();
        } finally {
          if (s10)
            throw a8;
        }
      }
      return i9;
    }(e19, t14) || function(e20, t15) {
      if (!e20)
        return;
      if ("string" == typeof e20)
        return w6(e20, t15);
      var n11 = Object.prototype.toString.call(e20).slice(8, -1);
      "Object" === n11 && e20.constructor && (n11 = e20.constructor.name);
      if ("Map" === n11 || "Set" === n11)
        return Array.from(e20);
      if ("Arguments" === n11 || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n11))
        return w6(e20, t15);
    }(e19, t14) || function() {
      throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.");
    }();
  }
  function w6(e19, t14) {
    (null == t14 || t14 > e19.length) && (t14 = e19.length);
    for (var n11 = 0, r8 = new Array(t14); n11 < t14; n11++)
      r8[n11] = e19[n11];
    return r8;
  }
  var E5 = "undefined" == typeof window ? null : window;
  var k5 = E5 ? E5.navigator : null;
  E5 && E5.document;
  var C5 = g6("");
  var S6 = g6({});
  var D6 = g6(function() {
  });
  var P6 = "undefined" == typeof HTMLElement ? "undefined" : g6(HTMLElement);
  var T6 = function(e19) {
    return e19 && e19.instanceString && B5(e19.instanceString) ? e19.instanceString() : null;
  };
  var M6 = function(e19) {
    return null != e19 && g6(e19) == C5;
  };
  var B5 = function(e19) {
    return null != e19 && g6(e19) === D6;
  };
  var _5 = function(e19) {
    return !L5(e19) && (Array.isArray ? Array.isArray(e19) : null != e19 && e19 instanceof Array);
  };
  var N6 = function(e19) {
    return null != e19 && g6(e19) === S6 && !_5(e19) && e19.constructor === Object;
  };
  var I6 = function(e19) {
    return null != e19 && g6(e19) === g6(1) && !isNaN(e19);
  };
  var z5 = function(e19) {
    return "undefined" === P6 ? void 0 : null != e19 && e19 instanceof HTMLElement;
  };
  var L5 = function(e19) {
    return A6(e19) || O6(e19);
  };
  var A6 = function(e19) {
    return "collection" === T6(e19) && e19._private.single;
  };
  var O6 = function(e19) {
    return "collection" === T6(e19) && !e19._private.single;
  };
  var R4 = function(e19) {
    return "core" === T6(e19);
  };
  var V4 = function(e19) {
    return "stylesheet" === T6(e19);
  };
  var F5 = function(e19) {
    return null == e19 || !("" !== e19 && !e19.match(/^\s+$/));
  };
  var q5 = function(e19) {
    return function(e20) {
      return null != e20 && g6(e20) === S6;
    }(e19) && B5(e19.then);
  };
  var j6 = function(e19, t14) {
    t14 || (t14 = function() {
      if (1 === arguments.length)
        return arguments[0];
      if (0 === arguments.length)
        return "undefined";
      for (var e20 = [], t15 = 0; t15 < arguments.length; t15++)
        e20.push(arguments[t15]);
      return e20.join("$");
    });
    var n11 = function n12() {
      var r8, a8 = arguments, i9 = t14.apply(this, a8), o11 = n12.cache;
      return (r8 = o11[i9]) || (r8 = o11[i9] = e19.apply(this, a8)), r8;
    };
    return n11.cache = {}, n11;
  };
  var Y4 = j6(function(e19) {
    return e19.replace(/([A-Z])/g, function(e20) {
      return "-" + e20.toLowerCase();
    });
  });
  var X4 = j6(function(e19) {
    return e19.replace(/(-\w)/g, function(e20) {
      return e20[1].toUpperCase();
    });
  });
  var W5 = j6(function(e19, t14) {
    return e19 + t14[0].toUpperCase() + t14.substring(1);
  }, function(e19, t14) {
    return e19 + "$" + t14;
  });
  var H5 = function(e19) {
    return F5(e19) ? e19 : e19.charAt(0).toUpperCase() + e19.substring(1);
  };
  var K4 = "(?:[-+]?(?:(?:\\d+|\\d*\\.\\d+)(?:[Ee][+-]?\\d+)?))";
  var G4 = "rgb[a]?\\((" + K4 + "[%]?)\\s*,\\s*(" + K4 + "[%]?)\\s*,\\s*(" + K4 + "[%]?)(?:\\s*,\\s*(" + K4 + "))?\\)";
  var U5 = "rgb[a]?\\((?:" + K4 + "[%]?)\\s*,\\s*(?:" + K4 + "[%]?)\\s*,\\s*(?:" + K4 + "[%]?)(?:\\s*,\\s*(?:" + K4 + "))?\\)";
  var Z4 = "hsl[a]?\\((" + K4 + ")\\s*,\\s*(" + K4 + "[%])\\s*,\\s*(" + K4 + "[%])(?:\\s*,\\s*(" + K4 + "))?\\)";
  var $5 = "hsl[a]?\\((?:" + K4 + ")\\s*,\\s*(?:" + K4 + "[%])\\s*,\\s*(?:" + K4 + "[%])(?:\\s*,\\s*(?:" + K4 + "))?\\)";
  var Q4 = function(e19, t14) {
    return e19 < t14 ? -1 : e19 > t14 ? 1 : 0;
  };
  var J4 = null != Object.assign ? Object.assign.bind(Object) : function(e19) {
    for (var t14 = arguments, n11 = 1; n11 < t14.length; n11++) {
      var r8 = t14[n11];
      if (null != r8)
        for (var a8 = Object.keys(r8), i9 = 0; i9 < a8.length; i9++) {
          var o11 = a8[i9];
          e19[o11] = r8[o11];
        }
    }
    return e19;
  };
  var ee = function(e19) {
    return (_5(e19) ? e19 : null) || function(e20) {
      return te[e20.toLowerCase()];
    }(e19) || function(e20) {
      if ((4 === e20.length || 7 === e20.length) && "#" === e20[0]) {
        var t14, n11, r8, a8 = 16;
        return 4 === e20.length ? (t14 = parseInt(e20[1] + e20[1], a8), n11 = parseInt(e20[2] + e20[2], a8), r8 = parseInt(e20[3] + e20[3], a8)) : (t14 = parseInt(e20[1] + e20[2], a8), n11 = parseInt(e20[3] + e20[4], a8), r8 = parseInt(e20[5] + e20[6], a8)), [t14, n11, r8];
      }
    }(e19) || function(e20) {
      var t14, n11 = new RegExp("^" + G4 + "$").exec(e20);
      if (n11) {
        t14 = [];
        for (var r8 = [], a8 = 1; a8 <= 3; a8++) {
          var i9 = n11[a8];
          if ("%" === i9[i9.length - 1] && (r8[a8] = true), i9 = parseFloat(i9), r8[a8] && (i9 = i9 / 100 * 255), i9 < 0 || i9 > 255)
            return;
          t14.push(Math.floor(i9));
        }
        var o11 = r8[1] || r8[2] || r8[3], s10 = r8[1] && r8[2] && r8[3];
        if (o11 && !s10)
          return;
        var l10 = n11[4];
        if (void 0 !== l10) {
          if ((l10 = parseFloat(l10)) < 0 || l10 > 1)
            return;
          t14.push(l10);
        }
      }
      return t14;
    }(e19) || function(e20) {
      var t14, n11, r8, a8, i9, o11, s10, l10;
      function u9(e21, t15, n12) {
        return n12 < 0 && (n12 += 1), n12 > 1 && (n12 -= 1), n12 < 1 / 6 ? e21 + 6 * (t15 - e21) * n12 : n12 < 0.5 ? t15 : n12 < 2 / 3 ? e21 + (t15 - e21) * (2 / 3 - n12) * 6 : e21;
      }
      var c9 = new RegExp("^" + Z4 + "$").exec(e20);
      if (c9) {
        if ((n11 = parseInt(c9[1])) < 0 ? n11 = (360 - -1 * n11 % 360) % 360 : n11 > 360 && (n11 %= 360), n11 /= 360, (r8 = parseFloat(c9[2])) < 0 || r8 > 100)
          return;
        if (r8 /= 100, (a8 = parseFloat(c9[3])) < 0 || a8 > 100)
          return;
        if (a8 /= 100, void 0 !== (i9 = c9[4]) && ((i9 = parseFloat(i9)) < 0 || i9 > 1))
          return;
        if (0 === r8)
          o11 = s10 = l10 = Math.round(255 * a8);
        else {
          var d10 = a8 < 0.5 ? a8 * (1 + r8) : a8 + r8 - a8 * r8, h9 = 2 * a8 - d10;
          o11 = Math.round(255 * u9(h9, d10, n11 + 1 / 3)), s10 = Math.round(255 * u9(h9, d10, n11)), l10 = Math.round(255 * u9(h9, d10, n11 - 1 / 3));
        }
        t14 = [o11, s10, l10, i9];
      }
      return t14;
    }(e19);
  };
  var te = { transparent: [0, 0, 0, 0], aliceblue: [240, 248, 255], antiquewhite: [250, 235, 215], aqua: [0, 255, 255], aquamarine: [127, 255, 212], azure: [240, 255, 255], beige: [245, 245, 220], bisque: [255, 228, 196], black: [0, 0, 0], blanchedalmond: [255, 235, 205], blue: [0, 0, 255], blueviolet: [138, 43, 226], brown: [165, 42, 42], burlywood: [222, 184, 135], cadetblue: [95, 158, 160], chartreuse: [127, 255, 0], chocolate: [210, 105, 30], coral: [255, 127, 80], cornflowerblue: [100, 149, 237], cornsilk: [255, 248, 220], crimson: [220, 20, 60], cyan: [0, 255, 255], darkblue: [0, 0, 139], darkcyan: [0, 139, 139], darkgoldenrod: [184, 134, 11], darkgray: [169, 169, 169], darkgreen: [0, 100, 0], darkgrey: [169, 169, 169], darkkhaki: [189, 183, 107], darkmagenta: [139, 0, 139], darkolivegreen: [85, 107, 47], darkorange: [255, 140, 0], darkorchid: [153, 50, 204], darkred: [139, 0, 0], darksalmon: [233, 150, 122], darkseagreen: [143, 188, 143], darkslateblue: [72, 61, 139], darkslategray: [47, 79, 79], darkslategrey: [47, 79, 79], darkturquoise: [0, 206, 209], darkviolet: [148, 0, 211], deeppink: [255, 20, 147], deepskyblue: [0, 191, 255], dimgray: [105, 105, 105], dimgrey: [105, 105, 105], dodgerblue: [30, 144, 255], firebrick: [178, 34, 34], floralwhite: [255, 250, 240], forestgreen: [34, 139, 34], fuchsia: [255, 0, 255], gainsboro: [220, 220, 220], ghostwhite: [248, 248, 255], gold: [255, 215, 0], goldenrod: [218, 165, 32], gray: [128, 128, 128], grey: [128, 128, 128], green: [0, 128, 0], greenyellow: [173, 255, 47], honeydew: [240, 255, 240], hotpink: [255, 105, 180], indianred: [205, 92, 92], indigo: [75, 0, 130], ivory: [255, 255, 240], khaki: [240, 230, 140], lavender: [230, 230, 250], lavenderblush: [255, 240, 245], lawngreen: [124, 252, 0], lemonchiffon: [255, 250, 205], lightblue: [173, 216, 230], lightcoral: [240, 128, 128], lightcyan: [224, 255, 255], lightgoldenrodyellow: [250, 250, 210], lightgray: [211, 211, 211], lightgreen: [144, 238, 144], lightgrey: [211, 211, 211], lightpink: [255, 182, 193], lightsalmon: [255, 160, 122], lightseagreen: [32, 178, 170], lightskyblue: [135, 206, 250], lightslategray: [119, 136, 153], lightslategrey: [119, 136, 153], lightsteelblue: [176, 196, 222], lightyellow: [255, 255, 224], lime: [0, 255, 0], limegreen: [50, 205, 50], linen: [250, 240, 230], magenta: [255, 0, 255], maroon: [128, 0, 0], mediumaquamarine: [102, 205, 170], mediumblue: [0, 0, 205], mediumorchid: [186, 85, 211], mediumpurple: [147, 112, 219], mediumseagreen: [60, 179, 113], mediumslateblue: [123, 104, 238], mediumspringgreen: [0, 250, 154], mediumturquoise: [72, 209, 204], mediumvioletred: [199, 21, 133], midnightblue: [25, 25, 112], mintcream: [245, 255, 250], mistyrose: [255, 228, 225], moccasin: [255, 228, 181], navajowhite: [255, 222, 173], navy: [0, 0, 128], oldlace: [253, 245, 230], olive: [128, 128, 0], olivedrab: [107, 142, 35], orange: [255, 165, 0], orangered: [255, 69, 0], orchid: [218, 112, 214], palegoldenrod: [238, 232, 170], palegreen: [152, 251, 152], paleturquoise: [175, 238, 238], palevioletred: [219, 112, 147], papayawhip: [255, 239, 213], peachpuff: [255, 218, 185], peru: [205, 133, 63], pink: [255, 192, 203], plum: [221, 160, 221], powderblue: [176, 224, 230], purple: [128, 0, 128], red: [255, 0, 0], rosybrown: [188, 143, 143], royalblue: [65, 105, 225], saddlebrown: [139, 69, 19], salmon: [250, 128, 114], sandybrown: [244, 164, 96], seagreen: [46, 139, 87], seashell: [255, 245, 238], sienna: [160, 82, 45], silver: [192, 192, 192], skyblue: [135, 206, 235], slateblue: [106, 90, 205], slategray: [112, 128, 144], slategrey: [112, 128, 144], snow: [255, 250, 250], springgreen: [0, 255, 127], steelblue: [70, 130, 180], tan: [210, 180, 140], teal: [0, 128, 128], thistle: [216, 191, 216], tomato: [255, 99, 71], turquoise: [64, 224, 208], violet: [238, 130, 238], wheat: [245, 222, 179], white: [255, 255, 255], whitesmoke: [245, 245, 245], yellow: [255, 255, 0], yellowgreen: [154, 205, 50] };
  var ne = function(e19) {
    for (var t14 = e19.map, n11 = e19.keys, r8 = n11.length, a8 = 0; a8 < r8; a8++) {
      var i9 = n11[a8];
      if (N6(i9))
        throw Error("Tried to set map with object key");
      a8 < n11.length - 1 ? (null == t14[i9] && (t14[i9] = {}), t14 = t14[i9]) : t14[i9] = e19.value;
    }
  };
  var re = function(e19) {
    for (var t14 = e19.map, n11 = e19.keys, r8 = n11.length, a8 = 0; a8 < r8; a8++) {
      var i9 = n11[a8];
      if (N6(i9))
        throw Error("Tried to get map with object key");
      if (null == (t14 = t14[i9]))
        return t14;
    }
    return t14;
  };
  var ae = E5 ? E5.performance : null;
  var ie = ae && ae.now ? function() {
    return ae.now();
  } : function() {
    return Date.now();
  };
  var oe = function() {
    if (E5) {
      if (E5.requestAnimationFrame)
        return function(e19) {
          E5.requestAnimationFrame(e19);
        };
      if (E5.mozRequestAnimationFrame)
        return function(e19) {
          E5.mozRequestAnimationFrame(e19);
        };
      if (E5.webkitRequestAnimationFrame)
        return function(e19) {
          E5.webkitRequestAnimationFrame(e19);
        };
      if (E5.msRequestAnimationFrame)
        return function(e19) {
          E5.msRequestAnimationFrame(e19);
        };
    }
    return function(e19) {
      e19 && setTimeout(function() {
        e19(ie());
      }, 1e3 / 60);
    };
  }();
  var se = function(e19) {
    return oe(e19);
  };
  var le = ie;
  var ue = 9261;
  var ce = 5381;
  var de = function(e19) {
    for (var t14, n11 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : ue; !(t14 = e19.next()).done; )
      n11 = 65599 * n11 + t14.value | 0;
    return n11;
  };
  var he = function(e19) {
    return 65599 * (arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : ue) + e19 | 0;
  };
  var pe = function(e19) {
    var t14 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : ce;
    return (t14 << 5) + t14 + e19 | 0;
  };
  var fe = function(e19) {
    return 2097152 * e19[0] + e19[1];
  };
  var ge = function(e19, t14) {
    return [he(e19[0], t14[0]), pe(e19[1], t14[1])];
  };
  var ve = function(e19, t14) {
    var n11 = { value: 0, done: false }, r8 = 0, a8 = e19.length;
    return de({ next: function() {
      return r8 < a8 ? n11.value = e19.charCodeAt(r8++) : n11.done = true, n11;
    } }, t14);
  };
  var ye = function() {
    return me(arguments);
  };
  var me = function(e19) {
    for (var t14, n11 = 0; n11 < e19.length; n11++) {
      var r8 = e19[n11];
      t14 = 0 === n11 ? ve(r8) : ve(r8, t14);
    }
    return t14;
  };
  var be = true;
  var xe = null != console.warn;
  var we = null != console.trace;
  var Ee = Number.MAX_SAFE_INTEGER || 9007199254740991;
  var ke = function() {
    return true;
  };
  var Ce = function() {
    return false;
  };
  var Se = function() {
    return 0;
  };
  var De = function() {
  };
  var Pe = function(e19) {
    throw new Error(e19);
  };
  var Te = function(e19) {
    if (void 0 === e19)
      return be;
    be = !!e19;
  };
  var Me = function(e19) {
    Te() && (xe ? console.warn(e19) : (console.log(e19), we && console.trace()));
  };
  var Be = function(e19) {
    return null == e19 ? e19 : _5(e19) ? e19.slice() : N6(e19) ? function(e20) {
      return J4({}, e20);
    }(e19) : e19;
  };
  var _e = function(e19, t14) {
    for (t14 = e19 = ""; e19++ < 36; t14 += 51 * e19 & 52 ? (15 ^ e19 ? 8 ^ Math.random() * (20 ^ e19 ? 16 : 4) : 4).toString(16) : "-")
      ;
    return t14;
  };
  var Ne = {};
  var Ie = function() {
    return Ne;
  };
  var ze = function(e19) {
    var t14 = Object.keys(e19);
    return function(n11) {
      for (var r8 = {}, a8 = 0; a8 < t14.length; a8++) {
        var i9 = t14[a8], o11 = null == n11 ? void 0 : n11[i9];
        r8[i9] = void 0 === o11 ? e19[i9] : o11;
      }
      return r8;
    };
  };
  var Le = function(e19, t14, n11) {
    for (var r8 = e19.length - 1; r8 >= 0 && (e19[r8] !== t14 || (e19.splice(r8, 1), !n11)); r8--)
      ;
  };
  var Ae = function(e19) {
    e19.splice(0, e19.length);
  };
  var Oe = function(e19, t14, n11) {
    return n11 && (t14 = W5(n11, t14)), e19[t14];
  };
  var Re = function(e19, t14, n11, r8) {
    n11 && (t14 = W5(n11, t14)), e19[t14] = r8;
  };
  var Ve = "undefined" != typeof Map ? Map : function() {
    function e19() {
      v6(this, e19), this._obj = {};
    }
    return m7(e19, [{ key: "set", value: function(e20, t14) {
      return this._obj[e20] = t14, this;
    } }, { key: "delete", value: function(e20) {
      return this._obj[e20] = void 0, this;
    } }, { key: "clear", value: function() {
      this._obj = {};
    } }, { key: "has", value: function(e20) {
      return void 0 !== this._obj[e20];
    } }, { key: "get", value: function(e20) {
      return this._obj[e20];
    } }]), e19;
  }();
  var Fe = function() {
    function e19(t14) {
      if (v6(this, e19), this._obj = /* @__PURE__ */ Object.create(null), this.size = 0, null != t14) {
        var n11;
        n11 = null != t14.instanceString && t14.instanceString() === this.instanceString() ? t14.toArray() : t14;
        for (var r8 = 0; r8 < n11.length; r8++)
          this.add(n11[r8]);
      }
    }
    return m7(e19, [{ key: "instanceString", value: function() {
      return "set";
    } }, { key: "add", value: function(e20) {
      var t14 = this._obj;
      1 !== t14[e20] && (t14[e20] = 1, this.size++);
    } }, { key: "delete", value: function(e20) {
      var t14 = this._obj;
      1 === t14[e20] && (t14[e20] = 0, this.size--);
    } }, { key: "clear", value: function() {
      this._obj = /* @__PURE__ */ Object.create(null);
    } }, { key: "has", value: function(e20) {
      return 1 === this._obj[e20];
    } }, { key: "toArray", value: function() {
      var e20 = this;
      return Object.keys(this._obj).filter(function(t14) {
        return e20.has(t14);
      });
    } }, { key: "forEach", value: function(e20, t14) {
      return this.toArray().forEach(e20, t14);
    } }]), e19;
  }();
  var qe = "undefined" !== ("undefined" == typeof Set ? "undefined" : g6(Set)) ? Set : Fe;
  var je = function(e19, t14) {
    var n11 = !(arguments.length > 2 && void 0 !== arguments[2]) || arguments[2];
    if (void 0 !== e19 && void 0 !== t14 && R4(e19)) {
      var r8 = t14.group;
      if (null == r8 && (r8 = t14.data && null != t14.data.source && null != t14.data.target ? "edges" : "nodes"), "nodes" === r8 || "edges" === r8) {
        this.length = 1, this[0] = this;
        var a8 = this._private = { cy: e19, single: true, data: t14.data || {}, position: t14.position || { x: 0, y: 0 }, autoWidth: void 0, autoHeight: void 0, autoPadding: void 0, compoundBoundsClean: false, listeners: [], group: r8, style: {}, rstyle: {}, styleCxts: [], styleKeys: {}, removed: true, selected: !!t14.selected, selectable: void 0 === t14.selectable || !!t14.selectable, locked: !!t14.locked, grabbed: false, grabbable: void 0 === t14.grabbable || !!t14.grabbable, pannable: void 0 === t14.pannable ? "edges" === r8 : !!t14.pannable, active: false, classes: new qe(), animation: { current: [], queue: [] }, rscratch: {}, scratch: t14.scratch || {}, edges: [], children: [], parent: t14.parent && t14.parent.isNode() ? t14.parent : null, traversalCache: {}, backgrounding: false, bbCache: null, bbCacheShift: { x: 0, y: 0 }, bodyBounds: null, overlayBounds: null, labelBounds: { all: null, source: null, target: null, main: null }, arrowBounds: { source: null, target: null, "mid-source": null, "mid-target": null } };
        if (null == a8.position.x && (a8.position.x = 0), null == a8.position.y && (a8.position.y = 0), t14.renderedPosition) {
          var i9 = t14.renderedPosition, o11 = e19.pan(), s10 = e19.zoom();
          a8.position = { x: (i9.x - o11.x) / s10, y: (i9.y - o11.y) / s10 };
        }
        var l10 = [];
        _5(t14.classes) ? l10 = t14.classes : M6(t14.classes) && (l10 = t14.classes.split(/\s+/));
        for (var u9 = 0, c9 = l10.length; u9 < c9; u9++) {
          var d10 = l10[u9];
          d10 && "" !== d10 && a8.classes.add(d10);
        }
        this.createEmitter();
        var h9 = t14.style || t14.css;
        h9 && (Me("Setting a `style` bypass at element creation should be done only when absolutely necessary.  Try to use the stylesheet instead."), this.style(h9)), (void 0 === n11 || n11) && this.restore();
      } else
        Pe("An element must be of type `nodes` or `edges`; you specified `" + r8 + "`");
    } else
      Pe("An element must have a core reference and parameters set");
  };
  var Ye = function(e19) {
    return e19 = { bfs: e19.bfs || !e19.dfs, dfs: e19.dfs || !e19.bfs }, function(t14, n11, r8) {
      var a8;
      N6(t14) && !L5(t14) && (t14 = (a8 = t14).roots || a8.root, n11 = a8.visit, r8 = a8.directed), r8 = 2 !== arguments.length || B5(n11) ? r8 : n11, n11 = B5(n11) ? n11 : function() {
      };
      for (var i9, o11 = this._private.cy, s10 = t14 = M6(t14) ? this.filter(t14) : t14, l10 = [], u9 = [], c9 = {}, d10 = {}, h9 = {}, p9 = 0, f10 = this.byGroup(), g8 = f10.nodes, v11 = f10.edges, y9 = 0; y9 < s10.length; y9++) {
        var m11 = s10[y9], b10 = m11.id();
        m11.isNode() && (l10.unshift(m11), e19.bfs && (h9[b10] = true, u9.push(m11)), d10[b10] = 0);
      }
      for (var x10 = function() {
        var t15 = e19.bfs ? l10.shift() : l10.pop(), a9 = t15.id();
        if (e19.dfs) {
          if (h9[a9])
            return "continue";
          h9[a9] = true, u9.push(t15);
        }
        var o12, s11 = d10[a9], f11 = c9[a9], y10 = null != f11 ? f11.source() : null, m12 = null != f11 ? f11.target() : null, b11 = null == f11 ? void 0 : t15.same(y10) ? m12[0] : y10[0];
        if (true === (o12 = n11(t15, f11, b11, p9++, s11)))
          return i9 = t15, "break";
        if (false === o12)
          return "break";
        for (var x11 = t15.connectedEdges().filter(function(e20) {
          return (!r8 || e20.source().same(t15)) && v11.has(e20);
        }), w10 = 0; w10 < x11.length; w10++) {
          var E9 = x11[w10], k10 = E9.connectedNodes().filter(function(e20) {
            return !e20.same(t15) && g8.has(e20);
          }), C9 = k10.id();
          0 === k10.length || h9[C9] || (k10 = k10[0], l10.push(k10), e19.bfs && (h9[C9] = true, u9.push(k10)), c9[C9] = E9, d10[C9] = d10[a9] + 1);
        }
      }; 0 !== l10.length; ) {
        var w9 = x10();
        if ("continue" !== w9 && "break" === w9)
          break;
      }
      for (var E8 = o11.collection(), k9 = 0; k9 < u9.length; k9++) {
        var C8 = u9[k9], S7 = c9[C8.id()];
        null != S7 && E8.push(S7), E8.push(C8);
      }
      return { path: o11.collection(E8), found: o11.collection(i9) };
    };
  };
  var Xe = { breadthFirstSearch: Ye({ bfs: true }), depthFirstSearch: Ye({ dfs: true }) };
  Xe.bfs = Xe.breadthFirstSearch, Xe.dfs = Xe.depthFirstSearch;
  var We = ze({ root: null, weight: function(e19) {
    return 1;
  }, directed: false });
  var He = { dijkstra: function(e19) {
    if (!N6(e19)) {
      var t14 = arguments;
      e19 = { root: t14[0], weight: t14[1], directed: t14[2] };
    }
    var n11 = We(e19), r8 = n11.root, a8 = n11.weight, i9 = n11.directed, o11 = this, s10 = a8, l10 = M6(r8) ? this.filter(r8)[0] : r8[0], u9 = {}, c9 = {}, h9 = {}, p9 = this.byGroup(), f10 = p9.nodes, g8 = p9.edges;
    g8.unmergeBy(function(e20) {
      return e20.isLoop();
    });
    for (var v11 = function(e20) {
      return u9[e20.id()];
    }, y9 = function(e20, t15) {
      u9[e20.id()] = t15, m11.updateItem(e20);
    }, m11 = new d6.default(function(e20, t15) {
      return v11(e20) - v11(t15);
    }), b10 = 0; b10 < f10.length; b10++) {
      var x10 = f10[b10];
      u9[x10.id()] = x10.same(l10) ? 0 : 1 / 0, m11.push(x10);
    }
    for (var w9 = function(e20, t15) {
      for (var n12, r9 = (i9 ? e20.edgesTo(t15) : e20.edgesWith(t15)).intersect(g8), a9 = 1 / 0, o12 = 0; o12 < r9.length; o12++) {
        var l11 = r9[o12], u10 = s10(l11);
        (u10 < a9 || !n12) && (a9 = u10, n12 = l11);
      }
      return { edge: n12, dist: a9 };
    }; m11.size() > 0; ) {
      var E8 = m11.pop(), k9 = v11(E8), C8 = E8.id();
      if (h9[C8] = k9, k9 !== 1 / 0)
        for (var S7 = E8.neighborhood().intersect(f10), D7 = 0; D7 < S7.length; D7++) {
          var P9 = S7[D7], T8 = P9.id(), B8 = w9(E8, P9), _6 = k9 + B8.dist;
          _6 < v11(P9) && (y9(P9, _6), c9[T8] = { node: E8, edge: B8.edge });
        }
    }
    return { distanceTo: function(e20) {
      var t15 = M6(e20) ? f10.filter(e20)[0] : e20[0];
      return h9[t15.id()];
    }, pathTo: function(e20) {
      var t15 = M6(e20) ? f10.filter(e20)[0] : e20[0], n12 = [], r9 = t15, a9 = r9.id();
      if (t15.length > 0)
        for (n12.unshift(t15); c9[a9]; ) {
          var i10 = c9[a9];
          n12.unshift(i10.edge), n12.unshift(i10.node), a9 = (r9 = i10.node).id();
        }
      return o11.spawn(n12);
    } };
  } };
  var Ke = { kruskal: function(e19) {
    e19 = e19 || function(e20) {
      return 1;
    };
    for (var t14 = this.byGroup(), n11 = t14.nodes, r8 = t14.edges, a8 = n11.length, i9 = new Array(a8), o11 = n11, s10 = function(e20) {
      for (var t15 = 0; t15 < i9.length; t15++) {
        if (i9[t15].has(e20))
          return t15;
      }
    }, l10 = 0; l10 < a8; l10++)
      i9[l10] = this.spawn(n11[l10]);
    for (var u9 = r8.sort(function(t15, n12) {
      return e19(t15) - e19(n12);
    }), c9 = 0; c9 < u9.length; c9++) {
      var d10 = u9[c9], h9 = d10.source()[0], p9 = d10.target()[0], f10 = s10(h9), g8 = s10(p9), v11 = i9[f10], y9 = i9[g8];
      f10 !== g8 && (o11.merge(d10), v11.merge(y9), i9.splice(g8, 1));
    }
    return o11;
  } };
  var Ge = ze({ root: null, goal: null, weight: function(e19) {
    return 1;
  }, heuristic: function(e19) {
    return 0;
  }, directed: false });
  var Ue = { aStar: function(e19) {
    var t14 = this.cy(), n11 = Ge(e19), r8 = n11.root, a8 = n11.goal, i9 = n11.heuristic, o11 = n11.directed, s10 = n11.weight;
    r8 = t14.collection(r8)[0], a8 = t14.collection(a8)[0];
    var l10, u9, c9 = r8.id(), h9 = a8.id(), p9 = {}, f10 = {}, g8 = {}, v11 = new d6.default(function(e20, t15) {
      return f10[e20.id()] - f10[t15.id()];
    }), y9 = new qe(), m11 = {}, b10 = {}, x10 = function(e20, t15) {
      v11.push(e20), y9.add(t15);
    };
    x10(r8, c9), p9[c9] = 0, f10[c9] = i9(r8);
    for (var w9, E8 = 0; v11.size() > 0; ) {
      if (l10 = v11.pop(), u9 = l10.id(), y9.delete(u9), E8++, u9 === h9) {
        for (var k9 = [], C8 = a8, S7 = h9, D7 = b10[S7]; k9.unshift(C8), null != D7 && k9.unshift(D7), null != (C8 = m11[S7]); )
          D7 = b10[S7 = C8.id()];
        return { found: true, distance: p9[u9], path: this.spawn(k9), steps: E8 };
      }
      g8[u9] = true;
      for (var P9 = l10._private.edges, T8 = 0; T8 < P9.length; T8++) {
        var M8 = P9[T8];
        if (this.hasElementWithId(M8.id()) && (!o11 || M8.data("source") === u9)) {
          var B8 = M8.source(), _6 = M8.target(), N7 = B8.id() !== u9 ? B8 : _6, I7 = N7.id();
          if (this.hasElementWithId(I7) && !g8[I7]) {
            var z7 = p9[u9] + s10(M8);
            w9 = I7, y9.has(w9) ? z7 < p9[I7] && (p9[I7] = z7, f10[I7] = z7 + i9(N7), m11[I7] = l10, b10[I7] = M8) : (p9[I7] = z7, f10[I7] = z7 + i9(N7), x10(N7, I7), m11[I7] = l10, b10[I7] = M8);
          }
        }
      }
    }
    return { found: false, distance: void 0, path: void 0, steps: E8 };
  } };
  var Ze = ze({ weight: function(e19) {
    return 1;
  }, directed: false });
  var $e = { floydWarshall: function(e19) {
    for (var t14 = this.cy(), n11 = Ze(e19), r8 = n11.weight, a8 = n11.directed, i9 = r8, o11 = this.byGroup(), s10 = o11.nodes, l10 = o11.edges, u9 = s10.length, c9 = u9 * u9, d10 = function(e20) {
      return s10.indexOf(e20);
    }, h9 = function(e20) {
      return s10[e20];
    }, p9 = new Array(c9), f10 = 0; f10 < c9; f10++) {
      var g8 = f10 % u9, v11 = (f10 - g8) / u9;
      p9[f10] = v11 === g8 ? 0 : 1 / 0;
    }
    for (var y9 = new Array(c9), m11 = new Array(c9), b10 = 0; b10 < l10.length; b10++) {
      var x10 = l10[b10], w9 = x10.source()[0], E8 = x10.target()[0];
      if (w9 !== E8) {
        var k9 = d10(w9), C8 = d10(E8), S7 = k9 * u9 + C8, D7 = i9(x10);
        if (p9[S7] > D7 && (p9[S7] = D7, y9[S7] = C8, m11[S7] = x10), !a8) {
          var P9 = C8 * u9 + k9;
          !a8 && p9[P9] > D7 && (p9[P9] = D7, y9[P9] = k9, m11[P9] = x10);
        }
      }
    }
    for (var T8 = 0; T8 < u9; T8++)
      for (var B8 = 0; B8 < u9; B8++)
        for (var _6 = B8 * u9 + T8, N7 = 0; N7 < u9; N7++) {
          var I7 = B8 * u9 + N7, z7 = T8 * u9 + N7;
          p9[_6] + p9[z7] < p9[I7] && (p9[I7] = p9[_6] + p9[z7], y9[I7] = y9[_6]);
        }
    var L9 = function(e20) {
      return d10(function(e21) {
        return (M6(e21) ? t14.filter(e21) : e21)[0];
      }(e20));
    }, A9 = { distance: function(e20, t15) {
      var n12 = L9(e20), r9 = L9(t15);
      return p9[n12 * u9 + r9];
    }, path: function(e20, n12) {
      var r9 = L9(e20), a9 = L9(n12), i10 = h9(r9);
      if (r9 === a9)
        return i10.collection();
      if (null == y9[r9 * u9 + a9])
        return t14.collection();
      var o12, s11 = t14.collection(), l11 = r9;
      for (s11.merge(i10); r9 !== a9; )
        l11 = r9, r9 = y9[r9 * u9 + a9], o12 = m11[l11 * u9 + r9], s11.merge(o12), s11.merge(h9(r9));
      return s11;
    } };
    return A9;
  } };
  var Qe = ze({ weight: function(e19) {
    return 1;
  }, directed: false, root: null });
  var Je = { bellmanFord: function(e19) {
    var t14 = this, n11 = Qe(e19), r8 = n11.weight, a8 = n11.directed, i9 = n11.root, o11 = r8, s10 = this, l10 = this.cy(), u9 = this.byGroup(), c9 = u9.edges, d10 = u9.nodes, h9 = d10.length, p9 = new Ve(), f10 = false, g8 = [];
    i9 = l10.collection(i9)[0], c9.unmergeBy(function(e20) {
      return e20.isLoop();
    });
    for (var v11 = c9.length, y9 = function(e20) {
      var t15 = p9.get(e20.id());
      return t15 || (t15 = {}, p9.set(e20.id(), t15)), t15;
    }, m11 = function(e20) {
      return (M6(e20) ? l10.$(e20) : e20)[0];
    }, b10 = 0; b10 < h9; b10++) {
      var x10 = d10[b10], w9 = y9(x10);
      x10.same(i9) ? w9.dist = 0 : w9.dist = 1 / 0, w9.pred = null, w9.edge = null;
    }
    for (var E8 = false, k9 = function(e20, t15, n12, r9, a9, i10) {
      var o12 = r9.dist + i10;
      o12 < a9.dist && !n12.same(r9.edge) && (a9.dist = o12, a9.pred = e20, a9.edge = n12, E8 = true);
    }, C8 = 1; C8 < h9; C8++) {
      E8 = false;
      for (var S7 = 0; S7 < v11; S7++) {
        var D7 = c9[S7], P9 = D7.source(), T8 = D7.target(), B8 = o11(D7), _6 = y9(P9), N7 = y9(T8);
        k9(P9, 0, D7, _6, N7, B8), a8 || k9(T8, 0, D7, N7, _6, B8);
      }
      if (!E8)
        break;
    }
    if (E8)
      for (var I7 = [], z7 = 0; z7 < v11; z7++) {
        var L9 = c9[z7], A9 = L9.source(), O8 = L9.target(), R7 = o11(L9), V6 = y9(A9).dist, F7 = y9(O8).dist;
        if (V6 + R7 < F7 || !a8 && F7 + R7 < V6) {
          if (f10 || (Me("Graph contains a negative weight cycle for Bellman-Ford"), f10 = true), false === e19.findNegativeWeightCycles)
            break;
          var q7 = [];
          V6 + R7 < F7 && q7.push(A9), !a8 && F7 + R7 < V6 && q7.push(O8);
          for (var j8 = q7.length, Y5 = 0; Y5 < j8; Y5++) {
            var X5 = q7[Y5], W7 = [X5];
            W7.push(y9(X5).edge);
            for (var H8 = y9(X5).pred; -1 === W7.indexOf(H8); )
              W7.push(H8), W7.push(y9(H8).edge), H8 = y9(H8).pred;
            for (var K5 = (W7 = W7.slice(W7.indexOf(H8)))[0].id(), G5 = 0, U6 = 2; U6 < W7.length; U6 += 2)
              W7[U6].id() < K5 && (K5 = W7[U6].id(), G5 = U6);
            (W7 = W7.slice(G5).concat(W7.slice(0, G5))).push(W7[0]);
            var Z5 = W7.map(function(e20) {
              return e20.id();
            }).join(",");
            -1 === I7.indexOf(Z5) && (g8.push(s10.spawn(W7)), I7.push(Z5));
          }
        }
      }
    return { distanceTo: function(e20) {
      return y9(m11(e20)).dist;
    }, pathTo: function(e20) {
      for (var n12 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : i9, r9 = [], a9 = m11(e20); ; ) {
        if (null == a9)
          return t14.spawn();
        var o12 = y9(a9), l11 = o12.edge, u10 = o12.pred;
        if (r9.unshift(a9[0]), a9.same(n12) && r9.length > 0)
          break;
        null != l11 && r9.unshift(l11), a9 = u10;
      }
      return s10.spawn(r9);
    }, hasNegativeWeightCycle: f10, negativeWeightCycles: g8 };
  } };
  var et4 = Math.sqrt(2);
  var tt4 = function(e19, t14, n11) {
    0 === n11.length && Pe("Karger-Stein must be run on a connected (sub)graph");
    for (var r8 = n11[e19], a8 = r8[1], i9 = r8[2], o11 = t14[a8], s10 = t14[i9], l10 = n11, u9 = l10.length - 1; u9 >= 0; u9--) {
      var c9 = l10[u9], d10 = c9[1], h9 = c9[2];
      (t14[d10] === o11 && t14[h9] === s10 || t14[d10] === s10 && t14[h9] === o11) && l10.splice(u9, 1);
    }
    for (var p9 = 0; p9 < l10.length; p9++) {
      var f10 = l10[p9];
      f10[1] === s10 ? (l10[p9] = f10.slice(), l10[p9][1] = o11) : f10[2] === s10 && (l10[p9] = f10.slice(), l10[p9][2] = o11);
    }
    for (var g8 = 0; g8 < t14.length; g8++)
      t14[g8] === s10 && (t14[g8] = o11);
    return l10;
  };
  var nt4 = function(e19, t14, n11, r8) {
    for (; n11 > r8; ) {
      var a8 = Math.floor(Math.random() * t14.length);
      t14 = tt4(a8, e19, t14), n11--;
    }
    return t14;
  };
  var rt4 = { kargerStein: function() {
    var e19 = this, t14 = this.byGroup(), n11 = t14.nodes, r8 = t14.edges;
    r8.unmergeBy(function(e20) {
      return e20.isLoop();
    });
    var a8 = n11.length, i9 = r8.length, o11 = Math.ceil(Math.pow(Math.log(a8) / Math.LN2, 2)), s10 = Math.floor(a8 / et4);
    if (!(a8 < 2)) {
      for (var l10 = [], u9 = 0; u9 < i9; u9++) {
        var c9 = r8[u9];
        l10.push([u9, n11.indexOf(c9.source()), n11.indexOf(c9.target())]);
      }
      for (var d10 = 1 / 0, h9 = [], p9 = new Array(a8), f10 = new Array(a8), g8 = new Array(a8), v11 = function(e20, t15) {
        for (var n12 = 0; n12 < a8; n12++)
          t15[n12] = e20[n12];
      }, y9 = 0; y9 <= o11; y9++) {
        for (var m11 = 0; m11 < a8; m11++)
          f10[m11] = m11;
        var b10 = nt4(f10, l10.slice(), a8, s10), x10 = b10.slice();
        v11(f10, g8);
        var w9 = nt4(f10, b10, s10, 2), E8 = nt4(g8, x10, s10, 2);
        w9.length <= E8.length && w9.length < d10 ? (d10 = w9.length, h9 = w9, v11(f10, p9)) : E8.length <= w9.length && E8.length < d10 && (d10 = E8.length, h9 = E8, v11(g8, p9));
      }
      for (var k9 = this.spawn(h9.map(function(e20) {
        return r8[e20[0]];
      })), C8 = this.spawn(), S7 = this.spawn(), D7 = p9[0], P9 = 0; P9 < p9.length; P9++) {
        var T8 = p9[P9], M8 = n11[P9];
        T8 === D7 ? C8.merge(M8) : S7.merge(M8);
      }
      var B8 = function(t15) {
        var n12 = e19.spawn();
        return t15.forEach(function(t16) {
          n12.merge(t16), t16.connectedEdges().forEach(function(t17) {
            e19.contains(t17) && !k9.contains(t17) && n12.merge(t17);
          });
        }), n12;
      }, _6 = [B8(C8), B8(S7)];
      return { cut: k9, components: _6, partition1: C8, partition2: S7 };
    }
    Pe("At least 2 nodes are required for Karger-Stein algorithm");
  } };
  var at4 = function(e19, t14, n11) {
    return { x: e19.x * t14 + n11.x, y: e19.y * t14 + n11.y };
  };
  var it4 = function(e19, t14, n11) {
    return { x: (e19.x - n11.x) / t14, y: (e19.y - n11.y) / t14 };
  };
  var ot4 = function(e19) {
    return { x: e19[0], y: e19[1] };
  };
  var st4 = function(e19, t14) {
    return Math.atan2(t14, e19) - Math.PI / 2;
  };
  var lt4 = Math.log2 || function(e19) {
    return Math.log(e19) / Math.log(2);
  };
  var ut4 = function(e19) {
    return e19 > 0 ? 1 : e19 < 0 ? -1 : 0;
  };
  var ct4 = function(e19, t14) {
    return Math.sqrt(dt4(e19, t14));
  };
  var dt4 = function(e19, t14) {
    var n11 = t14.x - e19.x, r8 = t14.y - e19.y;
    return n11 * n11 + r8 * r8;
  };
  var ht4 = function(e19) {
    for (var t14 = e19.length, n11 = 0, r8 = 0; r8 < t14; r8++)
      n11 += e19[r8];
    for (var a8 = 0; a8 < t14; a8++)
      e19[a8] = e19[a8] / n11;
    return e19;
  };
  var pt4 = function(e19, t14, n11, r8) {
    return (1 - r8) * (1 - r8) * e19 + 2 * (1 - r8) * r8 * t14 + r8 * r8 * n11;
  };
  var ft4 = function(e19, t14, n11, r8) {
    return { x: pt4(e19.x, t14.x, n11.x, r8), y: pt4(e19.y, t14.y, n11.y, r8) };
  };
  var gt4 = function(e19, t14, n11) {
    return Math.max(e19, Math.min(n11, t14));
  };
  var vt4 = function(e19) {
    if (null == e19)
      return { x1: 1 / 0, y1: 1 / 0, x2: -1 / 0, y2: -1 / 0, w: 0, h: 0 };
    if (null != e19.x1 && null != e19.y1) {
      if (null != e19.x2 && null != e19.y2 && e19.x2 >= e19.x1 && e19.y2 >= e19.y1)
        return { x1: e19.x1, y1: e19.y1, x2: e19.x2, y2: e19.y2, w: e19.x2 - e19.x1, h: e19.y2 - e19.y1 };
      if (null != e19.w && null != e19.h && e19.w >= 0 && e19.h >= 0)
        return { x1: e19.x1, y1: e19.y1, x2: e19.x1 + e19.w, y2: e19.y1 + e19.h, w: e19.w, h: e19.h };
    }
  };
  var yt4 = function(e19, t14, n11) {
    e19.x1 = Math.min(e19.x1, t14), e19.x2 = Math.max(e19.x2, t14), e19.w = e19.x2 - e19.x1, e19.y1 = Math.min(e19.y1, n11), e19.y2 = Math.max(e19.y2, n11), e19.h = e19.y2 - e19.y1;
  };
  var mt4 = function(e19) {
    var t14 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : 0;
    return e19.x1 -= t14, e19.x2 += t14, e19.y1 -= t14, e19.y2 += t14, e19.w = e19.x2 - e19.x1, e19.h = e19.y2 - e19.y1, e19;
  };
  var bt4 = function(e19) {
    var t14, n11, r8, a8, i9 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : [0];
    if (1 === i9.length)
      t14 = n11 = r8 = a8 = i9[0];
    else if (2 === i9.length)
      t14 = r8 = i9[0], a8 = n11 = i9[1];
    else if (4 === i9.length) {
      var o11 = x6(i9, 4);
      t14 = o11[0], n11 = o11[1], r8 = o11[2], a8 = o11[3];
    }
    return e19.x1 -= a8, e19.x2 += n11, e19.y1 -= t14, e19.y2 += r8, e19.w = e19.x2 - e19.x1, e19.h = e19.y2 - e19.y1, e19;
  };
  var xt4 = function(e19, t14) {
    e19.x1 = t14.x1, e19.y1 = t14.y1, e19.x2 = t14.x2, e19.y2 = t14.y2, e19.w = e19.x2 - e19.x1, e19.h = e19.y2 - e19.y1;
  };
  var wt4 = function(e19, t14) {
    return !(e19.x1 > t14.x2) && (!(t14.x1 > e19.x2) && (!(e19.x2 < t14.x1) && (!(t14.x2 < e19.x1) && (!(e19.y2 < t14.y1) && (!(t14.y2 < e19.y1) && (!(e19.y1 > t14.y2) && !(t14.y1 > e19.y2)))))));
  };
  var Et4 = function(e19, t14, n11) {
    return e19.x1 <= t14 && t14 <= e19.x2 && e19.y1 <= n11 && n11 <= e19.y2;
  };
  var kt4 = function(e19, t14) {
    return Et4(e19, t14.x1, t14.y1) && Et4(e19, t14.x2, t14.y2);
  };
  var Ct4 = function(e19, t14, n11, r8, a8, i9, o11) {
    var s10, l10 = jt4(a8, i9), u9 = a8 / 2, c9 = i9 / 2, d10 = r8 - c9 - o11;
    if ((s10 = At4(e19, t14, n11, r8, n11 - u9 + l10 - o11, d10, n11 + u9 - l10 + o11, d10, false)).length > 0)
      return s10;
    var h9 = n11 + u9 + o11;
    if ((s10 = At4(e19, t14, n11, r8, h9, r8 - c9 + l10 - o11, h9, r8 + c9 - l10 + o11, false)).length > 0)
      return s10;
    var p9 = r8 + c9 + o11;
    if ((s10 = At4(e19, t14, n11, r8, n11 - u9 + l10 - o11, p9, n11 + u9 - l10 + o11, p9, false)).length > 0)
      return s10;
    var f10, g8 = n11 - u9 - o11;
    if ((s10 = At4(e19, t14, n11, r8, g8, r8 - c9 + l10 - o11, g8, r8 + c9 - l10 + o11, false)).length > 0)
      return s10;
    var v11 = n11 - u9 + l10, y9 = r8 - c9 + l10;
    if ((f10 = zt4(e19, t14, n11, r8, v11, y9, l10 + o11)).length > 0 && f10[0] <= v11 && f10[1] <= y9)
      return [f10[0], f10[1]];
    var m11 = n11 + u9 - l10, b10 = r8 - c9 + l10;
    if ((f10 = zt4(e19, t14, n11, r8, m11, b10, l10 + o11)).length > 0 && f10[0] >= m11 && f10[1] <= b10)
      return [f10[0], f10[1]];
    var x10 = n11 + u9 - l10, w9 = r8 + c9 - l10;
    if ((f10 = zt4(e19, t14, n11, r8, x10, w9, l10 + o11)).length > 0 && f10[0] >= x10 && f10[1] >= w9)
      return [f10[0], f10[1]];
    var E8 = n11 - u9 + l10, k9 = r8 + c9 - l10;
    return (f10 = zt4(e19, t14, n11, r8, E8, k9, l10 + o11)).length > 0 && f10[0] <= E8 && f10[1] >= k9 ? [f10[0], f10[1]] : [];
  };
  var St4 = function(e19, t14, n11, r8, a8, i9, o11) {
    var s10 = o11, l10 = Math.min(n11, a8), u9 = Math.max(n11, a8), c9 = Math.min(r8, i9), d10 = Math.max(r8, i9);
    return l10 - s10 <= e19 && e19 <= u9 + s10 && c9 - s10 <= t14 && t14 <= d10 + s10;
  };
  var Dt4 = function(e19, t14, n11, r8, a8, i9, o11, s10, l10) {
    var u9 = Math.min(n11, o11, a8) - l10, c9 = Math.max(n11, o11, a8) + l10, d10 = Math.min(r8, s10, i9) - l10, h9 = Math.max(r8, s10, i9) + l10;
    return !(e19 < u9 || e19 > c9 || t14 < d10 || t14 > h9);
  };
  var Pt4 = function(e19, t14, n11, r8, a8, i9, o11, s10) {
    var l10 = [];
    !function(e20, t15, n12, r9, a9) {
      var i10, o12, s11, l11, u10, c10, d11, h10;
      0 === e20 && (e20 = 1e-5), s11 = -27 * (r9 /= e20) + (t15 /= e20) * (9 * (n12 /= e20) - t15 * t15 * 2), i10 = (o12 = (3 * n12 - t15 * t15) / 9) * o12 * o12 + (s11 /= 54) * s11, a9[1] = 0, d11 = t15 / 3, i10 > 0 ? (u10 = (u10 = s11 + Math.sqrt(i10)) < 0 ? -Math.pow(-u10, 1 / 3) : Math.pow(u10, 1 / 3), c10 = (c10 = s11 - Math.sqrt(i10)) < 0 ? -Math.pow(-c10, 1 / 3) : Math.pow(c10, 1 / 3), a9[0] = -d11 + u10 + c10, d11 += (u10 + c10) / 2, a9[4] = a9[2] = -d11, d11 = Math.sqrt(3) * (-c10 + u10) / 2, a9[3] = d11, a9[5] = -d11) : (a9[5] = a9[3] = 0, 0 === i10 ? (h10 = s11 < 0 ? -Math.pow(-s11, 1 / 3) : Math.pow(s11, 1 / 3), a9[0] = 2 * h10 - d11, a9[4] = a9[2] = -(h10 + d11)) : (l11 = (o12 = -o12) * o12 * o12, l11 = Math.acos(s11 / Math.sqrt(l11)), h10 = 2 * Math.sqrt(o12), a9[0] = -d11 + h10 * Math.cos(l11 / 3), a9[2] = -d11 + h10 * Math.cos((l11 + 2 * Math.PI) / 3), a9[4] = -d11 + h10 * Math.cos((l11 + 4 * Math.PI) / 3)));
    }(1 * n11 * n11 - 4 * n11 * a8 + 2 * n11 * o11 + 4 * a8 * a8 - 4 * a8 * o11 + o11 * o11 + r8 * r8 - 4 * r8 * i9 + 2 * r8 * s10 + 4 * i9 * i9 - 4 * i9 * s10 + s10 * s10, 9 * n11 * a8 - 3 * n11 * n11 - 3 * n11 * o11 - 6 * a8 * a8 + 3 * a8 * o11 + 9 * r8 * i9 - 3 * r8 * r8 - 3 * r8 * s10 - 6 * i9 * i9 + 3 * i9 * s10, 3 * n11 * n11 - 6 * n11 * a8 + n11 * o11 - n11 * e19 + 2 * a8 * a8 + 2 * a8 * e19 - o11 * e19 + 3 * r8 * r8 - 6 * r8 * i9 + r8 * s10 - r8 * t14 + 2 * i9 * i9 + 2 * i9 * t14 - s10 * t14, 1 * n11 * a8 - n11 * n11 + n11 * e19 - a8 * e19 + r8 * i9 - r8 * r8 + r8 * t14 - i9 * t14, l10);
    for (var u9 = [], c9 = 0; c9 < 6; c9 += 2)
      Math.abs(l10[c9 + 1]) < 1e-7 && l10[c9] >= 0 && l10[c9] <= 1 && u9.push(l10[c9]);
    u9.push(1), u9.push(0);
    for (var d10, h9, p9, f10 = -1, g8 = 0; g8 < u9.length; g8++)
      d10 = Math.pow(1 - u9[g8], 2) * n11 + 2 * (1 - u9[g8]) * u9[g8] * a8 + u9[g8] * u9[g8] * o11, h9 = Math.pow(1 - u9[g8], 2) * r8 + 2 * (1 - u9[g8]) * u9[g8] * i9 + u9[g8] * u9[g8] * s10, p9 = Math.pow(d10 - e19, 2) + Math.pow(h9 - t14, 2), f10 >= 0 ? p9 < f10 && (f10 = p9) : f10 = p9;
    return f10;
  };
  var Tt4 = function(e19, t14, n11, r8, a8, i9) {
    var o11 = [e19 - n11, t14 - r8], s10 = [a8 - n11, i9 - r8], l10 = s10[0] * s10[0] + s10[1] * s10[1], u9 = o11[0] * o11[0] + o11[1] * o11[1], c9 = o11[0] * s10[0] + o11[1] * s10[1], d10 = c9 * c9 / l10;
    return c9 < 0 ? u9 : d10 > l10 ? (e19 - a8) * (e19 - a8) + (t14 - i9) * (t14 - i9) : u9 - d10;
  };
  var Mt4 = function(e19, t14, n11) {
    for (var r8, a8, i9, o11, s10 = 0, l10 = 0; l10 < n11.length / 2; l10++)
      if (r8 = n11[2 * l10], a8 = n11[2 * l10 + 1], l10 + 1 < n11.length / 2 ? (i9 = n11[2 * (l10 + 1)], o11 = n11[2 * (l10 + 1) + 1]) : (i9 = n11[2 * (l10 + 1 - n11.length / 2)], o11 = n11[2 * (l10 + 1 - n11.length / 2) + 1]), r8 == e19 && i9 == e19)
        ;
      else {
        if (!(r8 >= e19 && e19 >= i9 || r8 <= e19 && e19 <= i9))
          continue;
        (e19 - r8) / (i9 - r8) * (o11 - a8) + a8 > t14 && s10++;
      }
    return s10 % 2 != 0;
  };
  var Bt4 = function(e19, t14, n11, r8, a8, i9, o11, s10, l10) {
    var u9, c9 = new Array(n11.length);
    null != s10[0] ? (u9 = Math.atan(s10[1] / s10[0]), s10[0] < 0 ? u9 += Math.PI / 2 : u9 = -u9 - Math.PI / 2) : u9 = s10;
    for (var d10, h9 = Math.cos(-u9), p9 = Math.sin(-u9), f10 = 0; f10 < c9.length / 2; f10++)
      c9[2 * f10] = i9 / 2 * (n11[2 * f10] * h9 - n11[2 * f10 + 1] * p9), c9[2 * f10 + 1] = o11 / 2 * (n11[2 * f10 + 1] * h9 + n11[2 * f10] * p9), c9[2 * f10] += r8, c9[2 * f10 + 1] += a8;
    if (l10 > 0) {
      var g8 = Nt4(c9, -l10);
      d10 = _t4(g8);
    } else
      d10 = c9;
    return Mt4(e19, t14, d10);
  };
  var _t4 = function(e19) {
    for (var t14, n11, r8, a8, i9, o11, s10, l10, u9 = new Array(e19.length / 2), c9 = 0; c9 < e19.length / 4; c9++) {
      t14 = e19[4 * c9], n11 = e19[4 * c9 + 1], r8 = e19[4 * c9 + 2], a8 = e19[4 * c9 + 3], c9 < e19.length / 4 - 1 ? (i9 = e19[4 * (c9 + 1)], o11 = e19[4 * (c9 + 1) + 1], s10 = e19[4 * (c9 + 1) + 2], l10 = e19[4 * (c9 + 1) + 3]) : (i9 = e19[0], o11 = e19[1], s10 = e19[2], l10 = e19[3]);
      var d10 = At4(t14, n11, r8, a8, i9, o11, s10, l10, true);
      u9[2 * c9] = d10[0], u9[2 * c9 + 1] = d10[1];
    }
    return u9;
  };
  var Nt4 = function(e19, t14) {
    for (var n11, r8, a8, i9, o11 = new Array(2 * e19.length), s10 = 0; s10 < e19.length / 2; s10++) {
      n11 = e19[2 * s10], r8 = e19[2 * s10 + 1], s10 < e19.length / 2 - 1 ? (a8 = e19[2 * (s10 + 1)], i9 = e19[2 * (s10 + 1) + 1]) : (a8 = e19[0], i9 = e19[1]);
      var l10 = i9 - r8, u9 = -(a8 - n11), c9 = Math.sqrt(l10 * l10 + u9 * u9), d10 = l10 / c9, h9 = u9 / c9;
      o11[4 * s10] = n11 + d10 * t14, o11[4 * s10 + 1] = r8 + h9 * t14, o11[4 * s10 + 2] = a8 + d10 * t14, o11[4 * s10 + 3] = i9 + h9 * t14;
    }
    return o11;
  };
  var It4 = function(e19, t14, n11, r8, a8, i9, o11) {
    return e19 -= a8, t14 -= i9, (e19 /= n11 / 2 + o11) * e19 + (t14 /= r8 / 2 + o11) * t14 <= 1;
  };
  var zt4 = function(e19, t14, n11, r8, a8, i9, o11) {
    var s10 = [n11 - e19, r8 - t14], l10 = [e19 - a8, t14 - i9], u9 = s10[0] * s10[0] + s10[1] * s10[1], c9 = 2 * (l10[0] * s10[0] + l10[1] * s10[1]), d10 = c9 * c9 - 4 * u9 * (l10[0] * l10[0] + l10[1] * l10[1] - o11 * o11);
    if (d10 < 0)
      return [];
    var h9 = (-c9 + Math.sqrt(d10)) / (2 * u9), p9 = (-c9 - Math.sqrt(d10)) / (2 * u9), f10 = Math.min(h9, p9), g8 = Math.max(h9, p9), v11 = [];
    if (f10 >= 0 && f10 <= 1 && v11.push(f10), g8 >= 0 && g8 <= 1 && v11.push(g8), 0 === v11.length)
      return [];
    var y9 = v11[0] * s10[0] + e19, m11 = v11[0] * s10[1] + t14;
    return v11.length > 1 ? v11[0] == v11[1] ? [y9, m11] : [y9, m11, v11[1] * s10[0] + e19, v11[1] * s10[1] + t14] : [y9, m11];
  };
  var Lt4 = function(e19, t14, n11) {
    return t14 <= e19 && e19 <= n11 || n11 <= e19 && e19 <= t14 ? e19 : e19 <= t14 && t14 <= n11 || n11 <= t14 && t14 <= e19 ? t14 : n11;
  };
  var At4 = function(e19, t14, n11, r8, a8, i9, o11, s10, l10) {
    var u9 = e19 - a8, c9 = n11 - e19, d10 = o11 - a8, h9 = t14 - i9, p9 = r8 - t14, f10 = s10 - i9, g8 = d10 * h9 - f10 * u9, v11 = c9 * h9 - p9 * u9, y9 = f10 * c9 - d10 * p9;
    if (0 !== y9) {
      var m11 = g8 / y9, b10 = v11 / y9, x10 = -1e-3;
      return x10 <= m11 && m11 <= 1.001 && x10 <= b10 && b10 <= 1.001 || l10 ? [e19 + m11 * c9, t14 + m11 * p9] : [];
    }
    return 0 === g8 || 0 === v11 ? Lt4(e19, n11, o11) === o11 ? [o11, s10] : Lt4(e19, n11, a8) === a8 ? [a8, i9] : Lt4(a8, o11, n11) === n11 ? [n11, r8] : [] : [];
  };
  var Ot4 = function(e19, t14, n11, r8, a8, i9, o11, s10) {
    var l10, u9, c9, d10, h9, p9, f10 = [], g8 = new Array(n11.length), v11 = true;
    if (null == i9 && (v11 = false), v11) {
      for (var y9 = 0; y9 < g8.length / 2; y9++)
        g8[2 * y9] = n11[2 * y9] * i9 + r8, g8[2 * y9 + 1] = n11[2 * y9 + 1] * o11 + a8;
      if (s10 > 0) {
        var m11 = Nt4(g8, -s10);
        u9 = _t4(m11);
      } else
        u9 = g8;
    } else
      u9 = n11;
    for (var b10 = 0; b10 < u9.length / 2; b10++)
      c9 = u9[2 * b10], d10 = u9[2 * b10 + 1], b10 < u9.length / 2 - 1 ? (h9 = u9[2 * (b10 + 1)], p9 = u9[2 * (b10 + 1) + 1]) : (h9 = u9[0], p9 = u9[1]), 0 !== (l10 = At4(e19, t14, r8, a8, c9, d10, h9, p9)).length && f10.push(l10[0], l10[1]);
    return f10;
  };
  var Rt4 = function(e19, t14, n11) {
    var r8 = [e19[0] - t14[0], e19[1] - t14[1]], a8 = Math.sqrt(r8[0] * r8[0] + r8[1] * r8[1]), i9 = (a8 - n11) / a8;
    return i9 < 0 && (i9 = 1e-5), [t14[0] + i9 * r8[0], t14[1] + i9 * r8[1]];
  };
  var Vt4 = function(e19, t14) {
    var n11 = qt4(e19, t14);
    return n11 = Ft4(n11);
  };
  var Ft4 = function(e19) {
    for (var t14, n11, r8 = e19.length / 2, a8 = 1 / 0, i9 = 1 / 0, o11 = -1 / 0, s10 = -1 / 0, l10 = 0; l10 < r8; l10++)
      t14 = e19[2 * l10], n11 = e19[2 * l10 + 1], a8 = Math.min(a8, t14), o11 = Math.max(o11, t14), i9 = Math.min(i9, n11), s10 = Math.max(s10, n11);
    for (var u9 = 2 / (o11 - a8), c9 = 2 / (s10 - i9), d10 = 0; d10 < r8; d10++)
      t14 = e19[2 * d10] = e19[2 * d10] * u9, n11 = e19[2 * d10 + 1] = e19[2 * d10 + 1] * c9, a8 = Math.min(a8, t14), o11 = Math.max(o11, t14), i9 = Math.min(i9, n11), s10 = Math.max(s10, n11);
    if (i9 < -1)
      for (var h9 = 0; h9 < r8; h9++)
        n11 = e19[2 * h9 + 1] = e19[2 * h9 + 1] + (-1 - i9);
    return e19;
  };
  var qt4 = function(e19, t14) {
    var n11 = 1 / e19 * 2 * Math.PI, r8 = e19 % 2 == 0 ? Math.PI / 2 + n11 / 2 : Math.PI / 2;
    r8 += t14;
    for (var a8, i9 = new Array(2 * e19), o11 = 0; o11 < e19; o11++)
      a8 = o11 * n11 + r8, i9[2 * o11] = Math.cos(a8), i9[2 * o11 + 1] = Math.sin(-a8);
    return i9;
  };
  var jt4 = function(e19, t14) {
    return Math.min(e19 / 4, t14 / 4, 8);
  };
  var Yt4 = function(e19, t14) {
    return Math.min(e19 / 10, t14 / 10, 8);
  };
  var Xt4 = function(e19, t14) {
    return { heightOffset: Math.min(15, 0.05 * t14), widthOffset: Math.min(100, 0.25 * e19), ctrlPtOffsetPct: 0.05 };
  };
  var Wt4 = ze({ dampingFactor: 0.8, precision: 1e-6, iterations: 200, weight: function(e19) {
    return 1;
  } });
  var Ht4 = { pageRank: function(e19) {
    for (var t14 = Wt4(e19), n11 = t14.dampingFactor, r8 = t14.precision, a8 = t14.iterations, i9 = t14.weight, o11 = this._private.cy, s10 = this.byGroup(), l10 = s10.nodes, u9 = s10.edges, c9 = l10.length, d10 = c9 * c9, h9 = u9.length, p9 = new Array(d10), f10 = new Array(c9), g8 = (1 - n11) / c9, v11 = 0; v11 < c9; v11++) {
      for (var y9 = 0; y9 < c9; y9++) {
        p9[v11 * c9 + y9] = 0;
      }
      f10[v11] = 0;
    }
    for (var m11 = 0; m11 < h9; m11++) {
      var b10 = u9[m11], x10 = b10.data("source"), w9 = b10.data("target");
      if (x10 !== w9) {
        var E8 = l10.indexOfId(x10), k9 = l10.indexOfId(w9), C8 = i9(b10);
        p9[k9 * c9 + E8] += C8, f10[E8] += C8;
      }
    }
    for (var S7 = 1 / c9 + g8, D7 = 0; D7 < c9; D7++)
      if (0 === f10[D7])
        for (var P9 = 0; P9 < c9; P9++) {
          p9[P9 * c9 + D7] = S7;
        }
      else
        for (var T8 = 0; T8 < c9; T8++) {
          var M8 = T8 * c9 + D7;
          p9[M8] = p9[M8] / f10[D7] + g8;
        }
    for (var B8, _6 = new Array(c9), N7 = new Array(c9), I7 = 0; I7 < c9; I7++)
      _6[I7] = 1;
    for (var z7 = 0; z7 < a8; z7++) {
      for (var L9 = 0; L9 < c9; L9++)
        N7[L9] = 0;
      for (var A9 = 0; A9 < c9; A9++)
        for (var O8 = 0; O8 < c9; O8++) {
          var R7 = A9 * c9 + O8;
          N7[A9] += p9[R7] * _6[O8];
        }
      ht4(N7), B8 = _6, _6 = N7, N7 = B8;
      for (var V6 = 0, F7 = 0; F7 < c9; F7++) {
        var q7 = B8[F7] - _6[F7];
        V6 += q7 * q7;
      }
      if (V6 < r8)
        break;
    }
    return { rank: function(e20) {
      return e20 = o11.collection(e20)[0], _6[l10.indexOf(e20)];
    } };
  } };
  var Kt4 = ze({ root: null, weight: function(e19) {
    return 1;
  }, directed: false, alpha: 0 });
  var Gt4 = { degreeCentralityNormalized: function(e19) {
    e19 = Kt4(e19);
    var t14 = this.cy(), n11 = this.nodes(), r8 = n11.length;
    if (e19.directed) {
      for (var a8 = {}, i9 = {}, o11 = 0, s10 = 0, l10 = 0; l10 < r8; l10++) {
        var u9 = n11[l10], c9 = u9.id();
        e19.root = u9;
        var d10 = this.degreeCentrality(e19);
        o11 < d10.indegree && (o11 = d10.indegree), s10 < d10.outdegree && (s10 = d10.outdegree), a8[c9] = d10.indegree, i9[c9] = d10.outdegree;
      }
      return { indegree: function(e20) {
        return 0 == o11 ? 0 : (M6(e20) && (e20 = t14.filter(e20)), a8[e20.id()] / o11);
      }, outdegree: function(e20) {
        return 0 === s10 ? 0 : (M6(e20) && (e20 = t14.filter(e20)), i9[e20.id()] / s10);
      } };
    }
    for (var h9 = {}, p9 = 0, f10 = 0; f10 < r8; f10++) {
      var g8 = n11[f10];
      e19.root = g8;
      var v11 = this.degreeCentrality(e19);
      p9 < v11.degree && (p9 = v11.degree), h9[g8.id()] = v11.degree;
    }
    return { degree: function(e20) {
      return 0 === p9 ? 0 : (M6(e20) && (e20 = t14.filter(e20)), h9[e20.id()] / p9);
    } };
  }, degreeCentrality: function(e19) {
    e19 = Kt4(e19);
    var t14 = this.cy(), n11 = this, r8 = e19, a8 = r8.root, i9 = r8.weight, o11 = r8.directed, s10 = r8.alpha;
    if (a8 = t14.collection(a8)[0], o11) {
      for (var l10 = a8.connectedEdges(), u9 = l10.filter(function(e20) {
        return e20.target().same(a8) && n11.has(e20);
      }), c9 = l10.filter(function(e20) {
        return e20.source().same(a8) && n11.has(e20);
      }), d10 = u9.length, h9 = c9.length, p9 = 0, f10 = 0, g8 = 0; g8 < u9.length; g8++)
        p9 += i9(u9[g8]);
      for (var v11 = 0; v11 < c9.length; v11++)
        f10 += i9(c9[v11]);
      return { indegree: Math.pow(d10, 1 - s10) * Math.pow(p9, s10), outdegree: Math.pow(h9, 1 - s10) * Math.pow(f10, s10) };
    }
    for (var y9 = a8.connectedEdges().intersection(n11), m11 = y9.length, b10 = 0, x10 = 0; x10 < y9.length; x10++)
      b10 += i9(y9[x10]);
    return { degree: Math.pow(m11, 1 - s10) * Math.pow(b10, s10) };
  } };
  Gt4.dc = Gt4.degreeCentrality, Gt4.dcn = Gt4.degreeCentralityNormalised = Gt4.degreeCentralityNormalized;
  var Ut4 = ze({ harmonic: true, weight: function() {
    return 1;
  }, directed: false, root: null });
  var Zt4 = { closenessCentralityNormalized: function(e19) {
    for (var t14 = Ut4(e19), n11 = t14.harmonic, r8 = t14.weight, a8 = t14.directed, i9 = this.cy(), o11 = {}, s10 = 0, l10 = this.nodes(), u9 = this.floydWarshall({ weight: r8, directed: a8 }), c9 = 0; c9 < l10.length; c9++) {
      for (var d10 = 0, h9 = l10[c9], p9 = 0; p9 < l10.length; p9++)
        if (c9 !== p9) {
          var f10 = u9.distance(h9, l10[p9]);
          d10 += n11 ? 1 / f10 : f10;
        }
      n11 || (d10 = 1 / d10), s10 < d10 && (s10 = d10), o11[h9.id()] = d10;
    }
    return { closeness: function(e20) {
      return 0 == s10 ? 0 : (e20 = M6(e20) ? i9.filter(e20)[0].id() : e20.id(), o11[e20] / s10);
    } };
  }, closenessCentrality: function(e19) {
    var t14 = Ut4(e19), n11 = t14.root, r8 = t14.weight, a8 = t14.directed, i9 = t14.harmonic;
    n11 = this.filter(n11)[0];
    for (var o11 = this.dijkstra({ root: n11, weight: r8, directed: a8 }), s10 = 0, l10 = this.nodes(), u9 = 0; u9 < l10.length; u9++) {
      var c9 = l10[u9];
      if (!c9.same(n11)) {
        var d10 = o11.distanceTo(c9);
        s10 += i9 ? 1 / d10 : d10;
      }
    }
    return i9 ? s10 : 1 / s10;
  } };
  Zt4.cc = Zt4.closenessCentrality, Zt4.ccn = Zt4.closenessCentralityNormalised = Zt4.closenessCentralityNormalized;
  var $t4 = ze({ weight: null, directed: false });
  var Qt4 = { betweennessCentrality: function(e19) {
    for (var t14 = $t4(e19), n11 = t14.directed, r8 = t14.weight, a8 = null != r8, i9 = this.cy(), o11 = this.nodes(), s10 = {}, l10 = {}, u9 = 0, c9 = function(e20, t15) {
      l10[e20] = t15, t15 > u9 && (u9 = t15);
    }, h9 = function(e20) {
      return l10[e20];
    }, p9 = 0; p9 < o11.length; p9++) {
      var f10 = o11[p9], g8 = f10.id();
      s10[g8] = n11 ? f10.outgoers().nodes() : f10.openNeighborhood().nodes(), c9(g8, 0);
    }
    for (var v11 = function(e20) {
      for (var t15 = o11[e20].id(), n12 = [], l11 = {}, u10 = {}, p10 = {}, f11 = new d6.default(function(e21, t16) {
        return p10[e21] - p10[t16];
      }), g9 = 0; g9 < o11.length; g9++) {
        var v12 = o11[g9].id();
        l11[v12] = [], u10[v12] = 0, p10[v12] = 1 / 0;
      }
      for (u10[t15] = 1, p10[t15] = 0, f11.push(t15); !f11.empty(); ) {
        var y10 = f11.pop();
        if (n12.push(y10), a8)
          for (var m12 = 0; m12 < s10[y10].length; m12++) {
            var b10 = s10[y10][m12], x10 = i9.getElementById(y10), w9 = void 0;
            w9 = x10.edgesTo(b10).length > 0 ? x10.edgesTo(b10)[0] : b10.edgesTo(x10)[0];
            var E8 = r8(w9);
            b10 = b10.id(), p10[b10] > p10[y10] + E8 && (p10[b10] = p10[y10] + E8, f11.nodes.indexOf(b10) < 0 ? f11.push(b10) : f11.updateItem(b10), u10[b10] = 0, l11[b10] = []), p10[b10] == p10[y10] + E8 && (u10[b10] = u10[b10] + u10[y10], l11[b10].push(y10));
          }
        else
          for (var k9 = 0; k9 < s10[y10].length; k9++) {
            var C8 = s10[y10][k9].id();
            p10[C8] == 1 / 0 && (f11.push(C8), p10[C8] = p10[y10] + 1), p10[C8] == p10[y10] + 1 && (u10[C8] = u10[C8] + u10[y10], l11[C8].push(y10));
          }
      }
      for (var S7 = {}, D7 = 0; D7 < o11.length; D7++)
        S7[o11[D7].id()] = 0;
      for (; n12.length > 0; ) {
        for (var P9 = n12.pop(), T8 = 0; T8 < l11[P9].length; T8++) {
          var M8 = l11[P9][T8];
          S7[M8] = S7[M8] + u10[M8] / u10[P9] * (1 + S7[P9]);
        }
        P9 != o11[e20].id() && c9(P9, h9(P9) + S7[P9]);
      }
    }, y9 = 0; y9 < o11.length; y9++)
      v11(y9);
    var m11 = { betweenness: function(e20) {
      var t15 = i9.collection(e20).id();
      return h9(t15);
    }, betweennessNormalized: function(e20) {
      if (0 == u9)
        return 0;
      var t15 = i9.collection(e20).id();
      return h9(t15) / u9;
    } };
    return m11.betweennessNormalised = m11.betweennessNormalized, m11;
  } };
  Qt4.bc = Qt4.betweennessCentrality;
  var Jt4 = ze({ expandFactor: 2, inflateFactor: 2, multFactor: 1, maxIterations: 20, attributes: [function(e19) {
    return 1;
  }] });
  var en = function(e19, t14) {
    for (var n11 = 0, r8 = 0; r8 < t14.length; r8++)
      n11 += t14[r8](e19);
    return n11;
  };
  var tn = function(e19, t14) {
    for (var n11, r8 = 0; r8 < t14; r8++) {
      n11 = 0;
      for (var a8 = 0; a8 < t14; a8++)
        n11 += e19[a8 * t14 + r8];
      for (var i9 = 0; i9 < t14; i9++)
        e19[i9 * t14 + r8] = e19[i9 * t14 + r8] / n11;
    }
  };
  var nn = function(e19, t14, n11) {
    for (var r8 = new Array(n11 * n11), a8 = 0; a8 < n11; a8++) {
      for (var i9 = 0; i9 < n11; i9++)
        r8[a8 * n11 + i9] = 0;
      for (var o11 = 0; o11 < n11; o11++)
        for (var s10 = 0; s10 < n11; s10++)
          r8[a8 * n11 + s10] += e19[a8 * n11 + o11] * t14[o11 * n11 + s10];
    }
    return r8;
  };
  var rn = function(e19, t14, n11) {
    for (var r8 = e19.slice(0), a8 = 1; a8 < n11; a8++)
      e19 = nn(e19, r8, t14);
    return e19;
  };
  var an = function(e19, t14, n11) {
    for (var r8 = new Array(t14 * t14), a8 = 0; a8 < t14 * t14; a8++)
      r8[a8] = Math.pow(e19[a8], n11);
    return tn(r8, t14), r8;
  };
  var on = function(e19, t14, n11, r8) {
    for (var a8 = 0; a8 < n11; a8++) {
      if (Math.round(e19[a8] * Math.pow(10, r8)) / Math.pow(10, r8) !== Math.round(t14[a8] * Math.pow(10, r8)) / Math.pow(10, r8))
        return false;
    }
    return true;
  };
  var sn = function(e19, t14) {
    for (var n11 = 0; n11 < e19.length; n11++)
      if (!t14[n11] || e19[n11].id() !== t14[n11].id())
        return false;
    return true;
  };
  var ln = function(e19) {
    for (var t14 = this.nodes(), n11 = this.edges(), r8 = this.cy(), a8 = function(e20) {
      return Jt4(e20);
    }(e19), i9 = {}, o11 = 0; o11 < t14.length; o11++)
      i9[t14[o11].id()] = o11;
    for (var s10, l10 = t14.length, u9 = l10 * l10, c9 = new Array(u9), d10 = 0; d10 < u9; d10++)
      c9[d10] = 0;
    for (var h9 = 0; h9 < n11.length; h9++) {
      var p9 = n11[h9], f10 = i9[p9.source().id()], g8 = i9[p9.target().id()], v11 = en(p9, a8.attributes);
      c9[f10 * l10 + g8] += v11, c9[g8 * l10 + f10] += v11;
    }
    !function(e20, t15, n12) {
      for (var r9 = 0; r9 < t15; r9++)
        e20[r9 * t15 + r9] = n12;
    }(c9, l10, a8.multFactor), tn(c9, l10);
    for (var y9 = true, m11 = 0; y9 && m11 < a8.maxIterations; )
      y9 = false, s10 = rn(c9, l10, a8.expandFactor), c9 = an(s10, l10, a8.inflateFactor), on(c9, s10, u9, 4) || (y9 = true), m11++;
    var b10 = function(e20, t15, n12, r9) {
      for (var a9 = [], i10 = 0; i10 < t15; i10++) {
        for (var o12 = [], s11 = 0; s11 < t15; s11++)
          Math.round(1e3 * e20[i10 * t15 + s11]) / 1e3 > 0 && o12.push(n12[s11]);
        0 !== o12.length && a9.push(r9.collection(o12));
      }
      return a9;
    }(c9, l10, t14, r8);
    return b10 = function(e20) {
      for (var t15 = 0; t15 < e20.length; t15++)
        for (var n12 = 0; n12 < e20.length; n12++)
          t15 != n12 && sn(e20[t15], e20[n12]) && e20.splice(n12, 1);
      return e20;
    }(b10), b10;
  };
  var un = { markovClustering: ln, mcl: ln };
  var cn = function(e19) {
    return e19;
  };
  var dn = function(e19, t14) {
    return Math.abs(t14 - e19);
  };
  var hn = function(e19, t14, n11) {
    return e19 + dn(t14, n11);
  };
  var pn = function(e19, t14, n11) {
    return e19 + Math.pow(n11 - t14, 2);
  };
  var fn = function(e19) {
    return Math.sqrt(e19);
  };
  var gn = function(e19, t14, n11) {
    return Math.max(e19, dn(t14, n11));
  };
  var vn = function(e19, t14, n11, r8, a8) {
    for (var i9 = arguments.length > 5 && void 0 !== arguments[5] ? arguments[5] : cn, o11 = r8, s10 = 0; s10 < e19; s10++)
      o11 = a8(o11, t14(s10), n11(s10));
    return i9(o11);
  };
  var yn = { euclidean: function(e19, t14, n11) {
    return e19 >= 2 ? vn(e19, t14, n11, 0, pn, fn) : vn(e19, t14, n11, 0, hn);
  }, squaredEuclidean: function(e19, t14, n11) {
    return vn(e19, t14, n11, 0, pn);
  }, manhattan: function(e19, t14, n11) {
    return vn(e19, t14, n11, 0, hn);
  }, max: function(e19, t14, n11) {
    return vn(e19, t14, n11, -1 / 0, gn);
  } };
  function mn(e19, t14, n11, r8, a8, i9) {
    var o11;
    return o11 = B5(e19) ? e19 : yn[e19] || yn.euclidean, 0 === t14 && B5(e19) ? o11(a8, i9) : o11(t14, n11, r8, a8, i9);
  }
  yn["squared-euclidean"] = yn.squaredEuclidean, yn.squaredeuclidean = yn.squaredEuclidean;
  var bn = ze({ k: 2, m: 2, sensitivityThreshold: 1e-4, distance: "euclidean", maxIterations: 10, attributes: [], testMode: false, testCentroids: null });
  var xn = function(e19) {
    return bn(e19);
  };
  var wn = function(e19, t14, n11, r8, a8) {
    var i9 = "kMedoids" !== a8 ? function(e20) {
      return n11[e20];
    } : function(e20) {
      return r8[e20](n11);
    }, o11 = n11, s10 = t14;
    return mn(e19, r8.length, i9, function(e20) {
      return r8[e20](t14);
    }, o11, s10);
  };
  var En = function(e19, t14, n11) {
    for (var r8 = n11.length, a8 = new Array(r8), i9 = new Array(r8), o11 = new Array(t14), s10 = null, l10 = 0; l10 < r8; l10++)
      a8[l10] = e19.min(n11[l10]).value, i9[l10] = e19.max(n11[l10]).value;
    for (var u9 = 0; u9 < t14; u9++) {
      s10 = [];
      for (var c9 = 0; c9 < r8; c9++)
        s10[c9] = Math.random() * (i9[c9] - a8[c9]) + a8[c9];
      o11[u9] = s10;
    }
    return o11;
  };
  var kn = function(e19, t14, n11, r8, a8) {
    for (var i9 = 1 / 0, o11 = 0, s10 = 0; s10 < t14.length; s10++) {
      var l10 = wn(n11, e19, t14[s10], r8, a8);
      l10 < i9 && (i9 = l10, o11 = s10);
    }
    return o11;
  };
  var Cn = function(e19, t14, n11) {
    for (var r8 = [], a8 = null, i9 = 0; i9 < t14.length; i9++)
      n11[(a8 = t14[i9]).id()] === e19 && r8.push(a8);
    return r8;
  };
  var Sn = function(e19, t14, n11) {
    for (var r8 = 0; r8 < e19.length; r8++)
      for (var a8 = 0; a8 < e19[r8].length; a8++) {
        if (Math.abs(e19[r8][a8] - t14[r8][a8]) > n11)
          return false;
      }
    return true;
  };
  var Dn = function(e19, t14, n11) {
    for (var r8 = 0; r8 < n11; r8++)
      if (e19 === t14[r8])
        return true;
    return false;
  };
  var Pn = function(e19, t14) {
    var n11 = new Array(t14);
    if (e19.length < 50)
      for (var r8 = 0; r8 < t14; r8++) {
        for (var a8 = e19[Math.floor(Math.random() * e19.length)]; Dn(a8, n11, r8); )
          a8 = e19[Math.floor(Math.random() * e19.length)];
        n11[r8] = a8;
      }
    else
      for (var i9 = 0; i9 < t14; i9++)
        n11[i9] = e19[Math.floor(Math.random() * e19.length)];
    return n11;
  };
  var Tn = function(e19, t14, n11) {
    for (var r8 = 0, a8 = 0; a8 < t14.length; a8++)
      r8 += wn("manhattan", t14[a8], e19, n11, "kMedoids");
    return r8;
  };
  var Mn = function(e19, t14, n11, r8, a8) {
    for (var i9, o11, s10 = 0; s10 < t14.length; s10++)
      for (var l10 = 0; l10 < e19.length; l10++)
        r8[s10][l10] = Math.pow(n11[s10][l10], a8.m);
    for (var u9 = 0; u9 < e19.length; u9++)
      for (var c9 = 0; c9 < a8.attributes.length; c9++) {
        i9 = 0, o11 = 0;
        for (var d10 = 0; d10 < t14.length; d10++)
          i9 += r8[d10][u9] * a8.attributes[c9](t14[d10]), o11 += r8[d10][u9];
        e19[u9][c9] = i9 / o11;
      }
  };
  var Bn = function(e19, t14, n11, r8, a8) {
    for (var i9 = 0; i9 < e19.length; i9++)
      t14[i9] = e19[i9].slice();
    for (var o11, s10, l10, u9 = 2 / (a8.m - 1), c9 = 0; c9 < n11.length; c9++)
      for (var d10 = 0; d10 < r8.length; d10++) {
        o11 = 0;
        for (var h9 = 0; h9 < n11.length; h9++)
          s10 = wn(a8.distance, r8[d10], n11[c9], a8.attributes, "cmeans"), l10 = wn(a8.distance, r8[d10], n11[h9], a8.attributes, "cmeans"), o11 += Math.pow(s10 / l10, u9);
        e19[d10][c9] = 1 / o11;
      }
  };
  var _n = function(e19) {
    var t14, n11, r8, a8, i9, o11 = this.cy(), s10 = this.nodes(), l10 = xn(e19);
    a8 = new Array(s10.length);
    for (var u9 = 0; u9 < s10.length; u9++)
      a8[u9] = new Array(l10.k);
    r8 = new Array(s10.length);
    for (var c9 = 0; c9 < s10.length; c9++)
      r8[c9] = new Array(l10.k);
    for (var d10 = 0; d10 < s10.length; d10++) {
      for (var h9 = 0, p9 = 0; p9 < l10.k; p9++)
        r8[d10][p9] = Math.random(), h9 += r8[d10][p9];
      for (var f10 = 0; f10 < l10.k; f10++)
        r8[d10][f10] = r8[d10][f10] / h9;
    }
    n11 = new Array(l10.k);
    for (var g8 = 0; g8 < l10.k; g8++)
      n11[g8] = new Array(l10.attributes.length);
    i9 = new Array(s10.length);
    for (var v11 = 0; v11 < s10.length; v11++)
      i9[v11] = new Array(l10.k);
    for (var y9 = true, m11 = 0; y9 && m11 < l10.maxIterations; )
      y9 = false, Mn(n11, s10, r8, i9, l10), Bn(r8, a8, n11, s10, l10), Sn(r8, a8, l10.sensitivityThreshold) || (y9 = true), m11++;
    return t14 = function(e20, t15, n12, r9) {
      for (var a9, i10, o12 = new Array(n12.k), s11 = 0; s11 < o12.length; s11++)
        o12[s11] = [];
      for (var l11 = 0; l11 < t15.length; l11++) {
        a9 = -1 / 0, i10 = -1;
        for (var u10 = 0; u10 < t15[0].length; u10++)
          t15[l11][u10] > a9 && (a9 = t15[l11][u10], i10 = u10);
        o12[i10].push(e20[l11]);
      }
      for (var c10 = 0; c10 < o12.length; c10++)
        o12[c10] = r9.collection(o12[c10]);
      return o12;
    }(s10, r8, l10, o11), { clusters: t14, degreeOfMembership: r8 };
  };
  var Nn = { kMeans: function(e19) {
    var t14, n11 = this.cy(), r8 = this.nodes(), a8 = null, i9 = xn(e19), o11 = new Array(i9.k), s10 = {};
    i9.testMode ? "number" == typeof i9.testCentroids ? (i9.testCentroids, t14 = En(r8, i9.k, i9.attributes)) : t14 = "object" === g6(i9.testCentroids) ? i9.testCentroids : En(r8, i9.k, i9.attributes) : t14 = En(r8, i9.k, i9.attributes);
    for (var l10, u9, c9, d10 = true, h9 = 0; d10 && h9 < i9.maxIterations; ) {
      for (var p9 = 0; p9 < r8.length; p9++)
        s10[(a8 = r8[p9]).id()] = kn(a8, t14, i9.distance, i9.attributes, "kMeans");
      d10 = false;
      for (var f10 = 0; f10 < i9.k; f10++) {
        var v11 = Cn(f10, r8, s10);
        if (0 !== v11.length) {
          for (var y9 = i9.attributes.length, m11 = t14[f10], b10 = new Array(y9), x10 = new Array(y9), w9 = 0; w9 < y9; w9++) {
            x10[w9] = 0;
            for (var E8 = 0; E8 < v11.length; E8++)
              a8 = v11[E8], x10[w9] += i9.attributes[w9](a8);
            b10[w9] = x10[w9] / v11.length, l10 = b10[w9], u9 = m11[w9], c9 = i9.sensitivityThreshold, Math.abs(u9 - l10) <= c9 || (d10 = true);
          }
          t14[f10] = b10, o11[f10] = n11.collection(v11);
        }
      }
      h9++;
    }
    return o11;
  }, kMedoids: function(e19) {
    var t14, n11, r8 = this.cy(), a8 = this.nodes(), i9 = null, o11 = xn(e19), s10 = new Array(o11.k), l10 = {}, u9 = new Array(o11.k);
    o11.testMode ? "number" == typeof o11.testCentroids || (t14 = "object" === g6(o11.testCentroids) ? o11.testCentroids : Pn(a8, o11.k)) : t14 = Pn(a8, o11.k);
    for (var c9 = true, d10 = 0; c9 && d10 < o11.maxIterations; ) {
      for (var h9 = 0; h9 < a8.length; h9++)
        l10[(i9 = a8[h9]).id()] = kn(i9, t14, o11.distance, o11.attributes, "kMedoids");
      c9 = false;
      for (var p9 = 0; p9 < t14.length; p9++) {
        var f10 = Cn(p9, a8, l10);
        if (0 !== f10.length) {
          u9[p9] = Tn(t14[p9], f10, o11.attributes);
          for (var v11 = 0; v11 < f10.length; v11++)
            (n11 = Tn(f10[v11], f10, o11.attributes)) < u9[p9] && (u9[p9] = n11, t14[p9] = f10[v11], c9 = true);
          s10[p9] = r8.collection(f10);
        }
      }
      d10++;
    }
    return s10;
  }, fuzzyCMeans: _n, fcm: _n };
  var In = ze({ distance: "euclidean", linkage: "min", mode: "threshold", threshold: 1 / 0, addDendrogram: false, dendrogramDepth: 0, attributes: [] });
  var zn = { single: "min", complete: "max" };
  var Ln = function(e19, t14, n11, r8, a8) {
    for (var i9, o11 = 0, s10 = 1 / 0, l10 = a8.attributes, u9 = function(e20, t15) {
      return mn(a8.distance, l10.length, function(t16) {
        return l10[t16](e20);
      }, function(e21) {
        return l10[e21](t15);
      }, e20, t15);
    }, c9 = 0; c9 < e19.length; c9++) {
      var d10 = e19[c9].key, h9 = n11[d10][r8[d10]];
      h9 < s10 && (o11 = d10, s10 = h9);
    }
    if ("threshold" === a8.mode && s10 >= a8.threshold || "dendrogram" === a8.mode && 1 === e19.length)
      return false;
    var p9, f10 = t14[o11], g8 = t14[r8[o11]];
    p9 = "dendrogram" === a8.mode ? { left: f10, right: g8, key: f10.key } : { value: f10.value.concat(g8.value), key: f10.key }, e19[f10.index] = p9, e19.splice(g8.index, 1), t14[f10.key] = p9;
    for (var v11 = 0; v11 < e19.length; v11++) {
      var y9 = e19[v11];
      f10.key === y9.key ? i9 = 1 / 0 : "min" === a8.linkage ? (i9 = n11[f10.key][y9.key], n11[f10.key][y9.key] > n11[g8.key][y9.key] && (i9 = n11[g8.key][y9.key])) : "max" === a8.linkage ? (i9 = n11[f10.key][y9.key], n11[f10.key][y9.key] < n11[g8.key][y9.key] && (i9 = n11[g8.key][y9.key])) : i9 = "mean" === a8.linkage ? (n11[f10.key][y9.key] * f10.size + n11[g8.key][y9.key] * g8.size) / (f10.size + g8.size) : "dendrogram" === a8.mode ? u9(y9.value, f10.value) : u9(y9.value[0], f10.value[0]), n11[f10.key][y9.key] = n11[y9.key][f10.key] = i9;
    }
    for (var m11 = 0; m11 < e19.length; m11++) {
      var b10 = e19[m11].key;
      if (r8[b10] === f10.key || r8[b10] === g8.key) {
        for (var x10 = b10, w9 = 0; w9 < e19.length; w9++) {
          var E8 = e19[w9].key;
          n11[b10][E8] < n11[b10][x10] && (x10 = E8);
        }
        r8[b10] = x10;
      }
      e19[m11].index = m11;
    }
    return f10.key = g8.key = f10.index = g8.index = null, true;
  };
  var An = function e7(t14, n11, r8) {
    t14 && (t14.value ? n11.push(t14.value) : (t14.left && e7(t14.left, n11), t14.right && e7(t14.right, n11)));
  };
  var On = function e8(t14, n11) {
    if (!t14)
      return "";
    if (t14.left && t14.right) {
      var r8 = e8(t14.left, n11), a8 = e8(t14.right, n11), i9 = n11.add({ group: "nodes", data: { id: r8 + "," + a8 } });
      return n11.add({ group: "edges", data: { source: r8, target: i9.id() } }), n11.add({ group: "edges", data: { source: a8, target: i9.id() } }), i9.id();
    }
    return t14.value ? t14.value.id() : void 0;
  };
  var Rn = function e9(t14, n11, r8) {
    if (!t14)
      return [];
    var a8 = [], i9 = [], o11 = [];
    return 0 === n11 ? (t14.left && An(t14.left, a8), t14.right && An(t14.right, i9), o11 = a8.concat(i9), [r8.collection(o11)]) : 1 === n11 ? t14.value ? [r8.collection(t14.value)] : (t14.left && An(t14.left, a8), t14.right && An(t14.right, i9), [r8.collection(a8), r8.collection(i9)]) : t14.value ? [r8.collection(t14.value)] : (t14.left && (a8 = e9(t14.left, n11 - 1, r8)), t14.right && (i9 = e9(t14.right, n11 - 1, r8)), a8.concat(i9));
  };
  var Vn = function(e19) {
    for (var t14 = this.cy(), n11 = this.nodes(), r8 = function(e20) {
      var t15 = In(e20), n12 = zn[t15.linkage];
      return null != n12 && (t15.linkage = n12), t15;
    }(e19), a8 = r8.attributes, i9 = function(e20, t15) {
      return mn(r8.distance, a8.length, function(t16) {
        return a8[t16](e20);
      }, function(e21) {
        return a8[e21](t15);
      }, e20, t15);
    }, o11 = [], s10 = [], l10 = [], u9 = [], c9 = 0; c9 < n11.length; c9++) {
      var d10 = { value: "dendrogram" === r8.mode ? n11[c9] : [n11[c9]], key: c9, index: c9 };
      o11[c9] = d10, u9[c9] = d10, s10[c9] = [], l10[c9] = 0;
    }
    for (var h9 = 0; h9 < o11.length; h9++)
      for (var p9 = 0; p9 <= h9; p9++) {
        var f10 = void 0;
        f10 = "dendrogram" === r8.mode ? h9 === p9 ? 1 / 0 : i9(o11[h9].value, o11[p9].value) : h9 === p9 ? 1 / 0 : i9(o11[h9].value[0], o11[p9].value[0]), s10[h9][p9] = f10, s10[p9][h9] = f10, f10 < s10[h9][l10[h9]] && (l10[h9] = p9);
      }
    for (var g8, v11 = Ln(o11, u9, s10, l10, r8); v11; )
      v11 = Ln(o11, u9, s10, l10, r8);
    return "dendrogram" === r8.mode ? (g8 = Rn(o11[0], r8.dendrogramDepth, t14), r8.addDendrogram && On(o11[0], t14)) : (g8 = new Array(o11.length), o11.forEach(function(e20, n12) {
      e20.key = e20.index = null, g8[n12] = t14.collection(e20.value);
    })), g8;
  };
  var Fn = { hierarchicalClustering: Vn, hca: Vn };
  var qn = ze({ distance: "euclidean", preference: "median", damping: 0.8, maxIterations: 1e3, minIterations: 100, attributes: [] });
  var jn = function(e19, t14, n11, r8) {
    var a8 = function(e20, t15) {
      return r8[t15](e20);
    };
    return -mn(e19, r8.length, function(e20) {
      return a8(t14, e20);
    }, function(e20) {
      return a8(n11, e20);
    }, t14, n11);
  };
  var Yn = function(e19, t14) {
    var n11 = null;
    return n11 = "median" === t14 ? function(e20) {
      var t15 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : 0, n12 = arguments.length > 2 && void 0 !== arguments[2] ? arguments[2] : e20.length, r8 = !(arguments.length > 4 && void 0 !== arguments[4]) || arguments[4], a8 = !(arguments.length > 5 && void 0 !== arguments[5]) || arguments[5];
      arguments.length > 3 && void 0 !== arguments[3] && !arguments[3] ? (n12 < e20.length && e20.splice(n12, e20.length - n12), t15 > 0 && e20.splice(0, t15)) : e20 = e20.slice(t15, n12);
      for (var i9 = 0, o11 = e20.length - 1; o11 >= 0; o11--) {
        var s10 = e20[o11];
        a8 ? isFinite(s10) || (e20[o11] = -1 / 0, i9++) : e20.splice(o11, 1);
      }
      r8 && e20.sort(function(e21, t16) {
        return e21 - t16;
      });
      var l10 = e20.length, u9 = Math.floor(l10 / 2);
      return l10 % 2 != 0 ? e20[u9 + 1 + i9] : (e20[u9 - 1 + i9] + e20[u9 + i9]) / 2;
    }(e19) : "mean" === t14 ? function(e20) {
      for (var t15 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : 0, n12 = arguments.length > 2 && void 0 !== arguments[2] ? arguments[2] : e20.length, r8 = 0, a8 = 0, i9 = t15; i9 < n12; i9++) {
        var o11 = e20[i9];
        isFinite(o11) && (r8 += o11, a8++);
      }
      return r8 / a8;
    }(e19) : "min" === t14 ? function(e20) {
      for (var t15 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : 0, n12 = arguments.length > 2 && void 0 !== arguments[2] ? arguments[2] : e20.length, r8 = 1 / 0, a8 = t15; a8 < n12; a8++) {
        var i9 = e20[a8];
        isFinite(i9) && (r8 = Math.min(i9, r8));
      }
      return r8;
    }(e19) : "max" === t14 ? function(e20) {
      for (var t15 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : 0, n12 = arguments.length > 2 && void 0 !== arguments[2] ? arguments[2] : e20.length, r8 = -1 / 0, a8 = t15; a8 < n12; a8++) {
        var i9 = e20[a8];
        isFinite(i9) && (r8 = Math.max(i9, r8));
      }
      return r8;
    }(e19) : t14, n11;
  };
  var Xn = function(e19, t14, n11) {
    for (var r8 = [], a8 = 0; a8 < e19; a8++) {
      for (var i9 = -1, o11 = -1 / 0, s10 = 0; s10 < n11.length; s10++) {
        var l10 = n11[s10];
        t14[a8 * e19 + l10] > o11 && (i9 = l10, o11 = t14[a8 * e19 + l10]);
      }
      i9 > 0 && r8.push(i9);
    }
    for (var u9 = 0; u9 < n11.length; u9++)
      r8[n11[u9]] = n11[u9];
    return r8;
  };
  var Wn = function(e19) {
    for (var t14, n11, r8, a8, i9, o11, s10 = this.cy(), l10 = this.nodes(), u9 = function(e20) {
      var t15 = e20.damping, n12 = e20.preference;
      0.5 <= t15 && t15 < 1 || Pe("Damping must range on [0.5, 1).  Got: ".concat(t15));
      var r9 = ["median", "mean", "min", "max"];
      return r9.some(function(e21) {
        return e21 === n12;
      }) || I6(n12) || Pe("Preference must be one of [".concat(r9.map(function(e21) {
        return "'".concat(e21, "'");
      }).join(", "), "] or a number.  Got: ").concat(n12)), qn(e20);
    }(e19), c9 = {}, d10 = 0; d10 < l10.length; d10++)
      c9[l10[d10].id()] = d10;
    n11 = (t14 = l10.length) * t14, r8 = new Array(n11);
    for (var h9 = 0; h9 < n11; h9++)
      r8[h9] = -1 / 0;
    for (var p9 = 0; p9 < t14; p9++)
      for (var f10 = 0; f10 < t14; f10++)
        p9 !== f10 && (r8[p9 * t14 + f10] = jn(u9.distance, l10[p9], l10[f10], u9.attributes));
    a8 = Yn(r8, u9.preference);
    for (var g8 = 0; g8 < t14; g8++)
      r8[g8 * t14 + g8] = a8;
    i9 = new Array(n11);
    for (var v11 = 0; v11 < n11; v11++)
      i9[v11] = 0;
    o11 = new Array(n11);
    for (var y9 = 0; y9 < n11; y9++)
      o11[y9] = 0;
    for (var m11 = new Array(t14), b10 = new Array(t14), x10 = new Array(t14), w9 = 0; w9 < t14; w9++)
      m11[w9] = 0, b10[w9] = 0, x10[w9] = 0;
    for (var E8, k9 = new Array(t14 * u9.minIterations), C8 = 0; C8 < k9.length; C8++)
      k9[C8] = 0;
    for (E8 = 0; E8 < u9.maxIterations; E8++) {
      for (var S7 = 0; S7 < t14; S7++) {
        for (var D7 = -1 / 0, P9 = -1 / 0, T8 = -1, M8 = 0, B8 = 0; B8 < t14; B8++)
          m11[B8] = i9[S7 * t14 + B8], (M8 = o11[S7 * t14 + B8] + r8[S7 * t14 + B8]) >= D7 ? (P9 = D7, D7 = M8, T8 = B8) : M8 > P9 && (P9 = M8);
        for (var _6 = 0; _6 < t14; _6++)
          i9[S7 * t14 + _6] = (1 - u9.damping) * (r8[S7 * t14 + _6] - D7) + u9.damping * m11[_6];
        i9[S7 * t14 + T8] = (1 - u9.damping) * (r8[S7 * t14 + T8] - P9) + u9.damping * m11[T8];
      }
      for (var N7 = 0; N7 < t14; N7++) {
        for (var z7 = 0, L9 = 0; L9 < t14; L9++)
          m11[L9] = o11[L9 * t14 + N7], b10[L9] = Math.max(0, i9[L9 * t14 + N7]), z7 += b10[L9];
        z7 -= b10[N7], b10[N7] = i9[N7 * t14 + N7], z7 += b10[N7];
        for (var A9 = 0; A9 < t14; A9++)
          o11[A9 * t14 + N7] = (1 - u9.damping) * Math.min(0, z7 - b10[A9]) + u9.damping * m11[A9];
        o11[N7 * t14 + N7] = (1 - u9.damping) * (z7 - b10[N7]) + u9.damping * m11[N7];
      }
      for (var O8 = 0, R7 = 0; R7 < t14; R7++) {
        var V6 = o11[R7 * t14 + R7] + i9[R7 * t14 + R7] > 0 ? 1 : 0;
        k9[E8 % u9.minIterations * t14 + R7] = V6, O8 += V6;
      }
      if (O8 > 0 && (E8 >= u9.minIterations - 1 || E8 == u9.maxIterations - 1)) {
        for (var F7 = 0, q7 = 0; q7 < t14; q7++) {
          x10[q7] = 0;
          for (var j8 = 0; j8 < u9.minIterations; j8++)
            x10[q7] += k9[j8 * t14 + q7];
          0 !== x10[q7] && x10[q7] !== u9.minIterations || F7++;
        }
        if (F7 === t14)
          break;
      }
    }
    for (var Y5 = function(e20, t15, n12) {
      for (var r9 = [], a9 = 0; a9 < e20; a9++)
        t15[a9 * e20 + a9] + n12[a9 * e20 + a9] > 0 && r9.push(a9);
      return r9;
    }(t14, i9, o11), X5 = function(e20, t15, n12) {
      for (var r9 = Xn(e20, t15, n12), a9 = 0; a9 < n12.length; a9++) {
        for (var i10 = [], o12 = 0; o12 < r9.length; o12++)
          r9[o12] === n12[a9] && i10.push(o12);
        for (var s11 = -1, l11 = -1 / 0, u10 = 0; u10 < i10.length; u10++) {
          for (var c10 = 0, d11 = 0; d11 < i10.length; d11++)
            c10 += t15[i10[d11] * e20 + i10[u10]];
          c10 > l11 && (s11 = u10, l11 = c10);
        }
        n12[a9] = i10[s11];
      }
      return Xn(e20, t15, n12);
    }(t14, r8, Y5), W7 = {}, H8 = 0; H8 < Y5.length; H8++)
      W7[Y5[H8]] = [];
    for (var K5 = 0; K5 < l10.length; K5++) {
      var G5 = X5[c9[l10[K5].id()]];
      null != G5 && W7[G5].push(l10[K5]);
    }
    for (var U6 = new Array(Y5.length), Z5 = 0; Z5 < Y5.length; Z5++)
      U6[Z5] = s10.collection(W7[Y5[Z5]]);
    return U6;
  };
  var Hn = { affinityPropagation: Wn, ap: Wn };
  var Kn = ze({ root: void 0, directed: false });
  var Gn = function() {
    var e19 = this, t14 = {}, n11 = 0, r8 = 0, a8 = [], i9 = [], o11 = {}, s10 = function s11(l11, u9, c9) {
      l11 === c9 && (r8 += 1), t14[u9] = { id: n11, low: n11++, cutVertex: false };
      var d10, h9, p9, f10, g8 = e19.getElementById(u9).connectedEdges().intersection(e19);
      0 === g8.size() ? a8.push(e19.spawn(e19.getElementById(u9))) : g8.forEach(function(n12) {
        d10 = n12.source().id(), h9 = n12.target().id(), (p9 = d10 === u9 ? h9 : d10) !== c9 && (f10 = n12.id(), o11[f10] || (o11[f10] = true, i9.push({ x: u9, y: p9, edge: n12 })), p9 in t14 ? t14[u9].low = Math.min(t14[u9].low, t14[p9].id) : (s11(l11, p9, u9), t14[u9].low = Math.min(t14[u9].low, t14[p9].low), t14[u9].id <= t14[p9].low && (t14[u9].cutVertex = true, function(n13, r9) {
          for (var o12 = i9.length - 1, s12 = [], l12 = e19.spawn(); i9[o12].x != n13 || i9[o12].y != r9; )
            s12.push(i9.pop().edge), o12--;
          s12.push(i9.pop().edge), s12.forEach(function(n14) {
            var r10 = n14.connectedNodes().intersection(e19);
            l12.merge(n14), r10.forEach(function(n15) {
              var r11 = n15.id(), a9 = n15.connectedEdges().intersection(e19);
              l12.merge(n15), t14[r11].cutVertex ? l12.merge(a9.filter(function(e20) {
                return e20.isLoop();
              })) : l12.merge(a9);
            });
          }), a8.push(l12);
        }(u9, p9))));
      });
    };
    e19.forEach(function(e20) {
      if (e20.isNode()) {
        var n12 = e20.id();
        n12 in t14 || (r8 = 0, s10(n12, n12), t14[n12].cutVertex = r8 > 1);
      }
    });
    var l10 = Object.keys(t14).filter(function(e20) {
      return t14[e20].cutVertex;
    }).map(function(t15) {
      return e19.getElementById(t15);
    });
    return { cut: e19.spawn(l10), components: a8 };
  };
  var Un = function() {
    var e19 = this, t14 = {}, n11 = 0, r8 = [], a8 = [], i9 = e19.spawn(e19), o11 = function o12(s10) {
      if (a8.push(s10), t14[s10] = { index: n11, low: n11++, explored: false }, e19.getElementById(s10).connectedEdges().intersection(e19).forEach(function(e20) {
        var n12 = e20.target().id();
        n12 !== s10 && (n12 in t14 || o12(n12), t14[n12].explored || (t14[s10].low = Math.min(t14[s10].low, t14[n12].low)));
      }), t14[s10].index === t14[s10].low) {
        for (var l10 = e19.spawn(); ; ) {
          var u9 = a8.pop();
          if (l10.merge(e19.getElementById(u9)), t14[u9].low = t14[s10].index, t14[u9].explored = true, u9 === s10)
            break;
        }
        var c9 = l10.edgesWith(l10), d10 = l10.merge(c9);
        r8.push(d10), i9 = i9.difference(d10);
      }
    };
    return e19.forEach(function(e20) {
      if (e20.isNode()) {
        var n12 = e20.id();
        n12 in t14 || o11(n12);
      }
    }), { cut: i9, components: r8 };
  };
  var Zn = {};
  [Xe, He, Ke, Ue, $e, Je, rt4, Ht4, Gt4, Zt4, Qt4, un, Nn, Fn, Hn, { hierholzer: function(e19) {
    if (!N6(e19)) {
      var t14 = arguments;
      e19 = { root: t14[0], directed: t14[1] };
    }
    var n11, r8, a8, i9 = Kn(e19), o11 = i9.root, s10 = i9.directed, l10 = this, u9 = false;
    o11 && (a8 = M6(o11) ? this.filter(o11)[0].id() : o11[0].id());
    var c9 = {}, d10 = {};
    s10 ? l10.forEach(function(e20) {
      var t15 = e20.id();
      if (e20.isNode()) {
        var a9 = e20.indegree(true), i10 = e20.outdegree(true), o12 = a9 - i10, s11 = i10 - a9;
        1 == o12 ? n11 ? u9 = true : n11 = t15 : 1 == s11 ? r8 ? u9 = true : r8 = t15 : (s11 > 1 || o12 > 1) && (u9 = true), c9[t15] = [], e20.outgoers().forEach(function(e21) {
          e21.isEdge() && c9[t15].push(e21.id());
        });
      } else
        d10[t15] = [void 0, e20.target().id()];
    }) : l10.forEach(function(e20) {
      var t15 = e20.id();
      e20.isNode() ? (e20.degree(true) % 2 && (n11 ? r8 ? u9 = true : r8 = t15 : n11 = t15), c9[t15] = [], e20.connectedEdges().forEach(function(e21) {
        return c9[t15].push(e21.id());
      })) : d10[t15] = [e20.source().id(), e20.target().id()];
    });
    var h9 = { found: false, trail: void 0 };
    if (u9)
      return h9;
    if (r8 && n11)
      if (s10) {
        if (a8 && r8 != a8)
          return h9;
        a8 = r8;
      } else {
        if (a8 && r8 != a8 && n11 != a8)
          return h9;
        a8 || (a8 = r8);
      }
    else
      a8 || (a8 = l10[0].id());
    var p9 = function(e20) {
      for (var t15, n12, r9, a9 = e20, i10 = [e20]; c9[a9].length; )
        t15 = c9[a9].shift(), n12 = d10[t15][0], a9 != (r9 = d10[t15][1]) ? (c9[r9] = c9[r9].filter(function(e21) {
          return e21 != t15;
        }), a9 = r9) : s10 || a9 == n12 || (c9[n12] = c9[n12].filter(function(e21) {
          return e21 != t15;
        }), a9 = n12), i10.unshift(t15), i10.unshift(a9);
      return i10;
    }, f10 = [], g8 = [];
    for (g8 = p9(a8); 1 != g8.length; )
      0 == c9[g8[0]].length ? (f10.unshift(l10.getElementById(g8.shift())), f10.unshift(l10.getElementById(g8.shift()))) : g8 = p9(g8.shift()).concat(g8);
    for (var v11 in f10.unshift(l10.getElementById(g8.shift())), c9)
      if (c9[v11].length)
        return h9;
    return h9.found = true, h9.trail = this.spawn(f10, true), h9;
  } }, { hopcroftTarjanBiconnected: Gn, htbc: Gn, htb: Gn, hopcroftTarjanBiconnectedComponents: Gn }, { tarjanStronglyConnected: Un, tsc: Un, tscc: Un, tarjanStronglyConnectedComponents: Un }].forEach(function(e19) {
    J4(Zn, e19);
  });
  var $n = function e10(t14) {
    if (!(this instanceof e10))
      return new e10(t14);
    this.id = "Thenable/1.0.7", this.state = 0, this.fulfillValue = void 0, this.rejectReason = void 0, this.onFulfilled = [], this.onRejected = [], this.proxy = { then: this.then.bind(this) }, "function" == typeof t14 && t14.call(this, this.fulfill.bind(this), this.reject.bind(this));
  };
  $n.prototype = { fulfill: function(e19) {
    return Qn(this, 1, "fulfillValue", e19);
  }, reject: function(e19) {
    return Qn(this, 2, "rejectReason", e19);
  }, then: function(e19, t14) {
    var n11 = this, r8 = new $n();
    return n11.onFulfilled.push(tr4(e19, r8, "fulfill")), n11.onRejected.push(tr4(t14, r8, "reject")), Jn(n11), r8.proxy;
  } };
  var Qn = function(e19, t14, n11, r8) {
    return 0 === e19.state && (e19.state = t14, e19[n11] = r8, Jn(e19)), e19;
  };
  var Jn = function(e19) {
    1 === e19.state ? er4(e19, "onFulfilled", e19.fulfillValue) : 2 === e19.state && er4(e19, "onRejected", e19.rejectReason);
  };
  var er4 = function(e19, t14, n11) {
    if (0 !== e19[t14].length) {
      var r8 = e19[t14];
      e19[t14] = [];
      var a8 = function() {
        for (var e20 = 0; e20 < r8.length; e20++)
          r8[e20](n11);
      };
      "function" == typeof setImmediate ? setImmediate(a8) : setTimeout(a8, 0);
    }
  };
  var tr4 = function(e19, t14, n11) {
    return function(r8) {
      if ("function" != typeof e19)
        t14[n11].call(t14, r8);
      else {
        var a8;
        try {
          a8 = e19(r8);
        } catch (e20) {
          return void t14.reject(e20);
        }
        nr4(t14, a8);
      }
    };
  };
  var nr4 = function e11(t14, n11) {
    if (t14 !== n11 && t14.proxy !== n11) {
      var r8;
      if ("object" === g6(n11) && null !== n11 || "function" == typeof n11)
        try {
          r8 = n11.then;
        } catch (e19) {
          return void t14.reject(e19);
        }
      if ("function" != typeof r8)
        t14.fulfill(n11);
      else {
        var a8 = false;
        try {
          r8.call(n11, function(r9) {
            a8 || (a8 = true, r9 === n11 ? t14.reject(new TypeError("circular thenable chain")) : e11(t14, r9));
          }, function(e19) {
            a8 || (a8 = true, t14.reject(e19));
          });
        } catch (e19) {
          a8 || t14.reject(e19);
        }
      }
    } else
      t14.reject(new TypeError("cannot resolve promise with itself"));
  };
  $n.all = function(e19) {
    return new $n(function(t14, n11) {
      for (var r8 = new Array(e19.length), a8 = 0, i9 = function(n12, i10) {
        r8[n12] = i10, ++a8 === e19.length && t14(r8);
      }, o11 = 0; o11 < e19.length; o11++)
        !function(t15) {
          var r9 = e19[t15];
          null != r9 && null != r9.then ? r9.then(function(e20) {
            i9(t15, e20);
          }, function(e20) {
            n11(e20);
          }) : i9(t15, r9);
        }(o11);
    });
  }, $n.resolve = function(e19) {
    return new $n(function(t14, n11) {
      t14(e19);
    });
  }, $n.reject = function(e19) {
    return new $n(function(t14, n11) {
      n11(e19);
    });
  };
  var rr4 = "undefined" != typeof Promise ? Promise : $n;
  var ar4 = function(e19, t14, n11) {
    var r8 = R4(e19), a8 = !r8, i9 = this._private = J4({ duration: 1e3 }, t14, n11);
    if (i9.target = e19, i9.style = i9.style || i9.css, i9.started = false, i9.playing = false, i9.hooked = false, i9.applying = false, i9.progress = 0, i9.completes = [], i9.frames = [], i9.complete && B5(i9.complete) && i9.completes.push(i9.complete), a8) {
      var o11 = e19.position();
      i9.startPosition = i9.startPosition || { x: o11.x, y: o11.y }, i9.startStyle = i9.startStyle || e19.cy().style().getAnimationStartStyle(e19, i9.style);
    }
    if (r8) {
      var s10 = e19.pan();
      i9.startPan = { x: s10.x, y: s10.y }, i9.startZoom = e19.zoom();
    }
    this.length = 1, this[0] = this;
  };
  var ir4 = ar4.prototype;
  J4(ir4, { instanceString: function() {
    return "animation";
  }, hook: function() {
    var e19 = this._private;
    if (!e19.hooked) {
      var t14 = e19.target._private.animation;
      (e19.queue ? t14.queue : t14.current).push(this), L5(e19.target) && e19.target.cy().addToAnimationPool(e19.target), e19.hooked = true;
    }
    return this;
  }, play: function() {
    var e19 = this._private;
    return 1 === e19.progress && (e19.progress = 0), e19.playing = true, e19.started = false, e19.stopped = false, this.hook(), this;
  }, playing: function() {
    return this._private.playing;
  }, apply: function() {
    var e19 = this._private;
    return e19.applying = true, e19.started = false, e19.stopped = false, this.hook(), this;
  }, applying: function() {
    return this._private.applying;
  }, pause: function() {
    var e19 = this._private;
    return e19.playing = false, e19.started = false, this;
  }, stop: function() {
    var e19 = this._private;
    return e19.playing = false, e19.started = false, e19.stopped = true, this;
  }, rewind: function() {
    return this.progress(0);
  }, fastforward: function() {
    return this.progress(1);
  }, time: function(e19) {
    var t14 = this._private;
    return void 0 === e19 ? t14.progress * t14.duration : this.progress(e19 / t14.duration);
  }, progress: function(e19) {
    var t14 = this._private, n11 = t14.playing;
    return void 0 === e19 ? t14.progress : (n11 && this.pause(), t14.progress = e19, t14.started = false, n11 && this.play(), this);
  }, completed: function() {
    return 1 === this._private.progress;
  }, reverse: function() {
    var e19 = this._private, t14 = e19.playing;
    t14 && this.pause(), e19.progress = 1 - e19.progress, e19.started = false;
    var n11 = function(t15, n12) {
      var r9 = e19[t15];
      null != r9 && (e19[t15] = e19[n12], e19[n12] = r9);
    };
    if (n11("zoom", "startZoom"), n11("pan", "startPan"), n11("position", "startPosition"), e19.style)
      for (var r8 = 0; r8 < e19.style.length; r8++) {
        var a8 = e19.style[r8], i9 = a8.name, o11 = e19.startStyle[i9];
        e19.startStyle[i9] = a8, e19.style[r8] = o11;
      }
    return t14 && this.play(), this;
  }, promise: function(e19) {
    var t14, n11 = this._private;
    if ("frame" === e19)
      t14 = n11.frames;
    else
      t14 = n11.completes;
    return new rr4(function(e20, n12) {
      t14.push(function() {
        e20();
      });
    });
  } }), ir4.complete = ir4.completed, ir4.run = ir4.play, ir4.running = ir4.playing;
  var or4 = { animated: function() {
    return function() {
      var e19 = this, t14 = void 0 !== e19.length ? e19 : [e19];
      if (!(this._private.cy || this).styleEnabled())
        return false;
      var n11 = t14[0];
      return n11 ? n11._private.animation.current.length > 0 : void 0;
    };
  }, clearQueue: function() {
    return function() {
      var e19 = this, t14 = void 0 !== e19.length ? e19 : [e19];
      if (!(this._private.cy || this).styleEnabled())
        return this;
      for (var n11 = 0; n11 < t14.length; n11++) {
        t14[n11]._private.animation.queue = [];
      }
      return this;
    };
  }, delay: function() {
    return function(e19, t14) {
      return (this._private.cy || this).styleEnabled() ? this.animate({ delay: e19, duration: e19, complete: t14 }) : this;
    };
  }, delayAnimation: function() {
    return function(e19, t14) {
      return (this._private.cy || this).styleEnabled() ? this.animation({ delay: e19, duration: e19, complete: t14 }) : this;
    };
  }, animation: function() {
    return function(e19, t14) {
      var n11 = this, r8 = void 0 !== n11.length, a8 = r8 ? n11 : [n11], i9 = this._private.cy || this, o11 = !r8, s10 = !o11;
      if (!i9.styleEnabled())
        return this;
      var l10 = i9.style();
      if (e19 = J4({}, e19, t14), 0 === Object.keys(e19).length)
        return new ar4(a8[0], e19);
      switch (void 0 === e19.duration && (e19.duration = 400), e19.duration) {
        case "slow":
          e19.duration = 600;
          break;
        case "fast":
          e19.duration = 200;
      }
      if (s10 && (e19.style = l10.getPropsList(e19.style || e19.css), e19.css = void 0), s10 && null != e19.renderedPosition) {
        var u9 = e19.renderedPosition, c9 = i9.pan(), d10 = i9.zoom();
        e19.position = it4(u9, d10, c9);
      }
      if (o11 && null != e19.panBy) {
        var h9 = e19.panBy, p9 = i9.pan();
        e19.pan = { x: p9.x + h9.x, y: p9.y + h9.y };
      }
      var f10 = e19.center || e19.centre;
      if (o11 && null != f10) {
        var g8 = i9.getCenterPan(f10.eles, e19.zoom);
        null != g8 && (e19.pan = g8);
      }
      if (o11 && null != e19.fit) {
        var v11 = e19.fit, y9 = i9.getFitViewport(v11.eles || v11.boundingBox, v11.padding);
        null != y9 && (e19.pan = y9.pan, e19.zoom = y9.zoom);
      }
      if (o11 && N6(e19.zoom)) {
        var m11 = i9.getZoomedViewport(e19.zoom);
        null != m11 ? (m11.zoomed && (e19.zoom = m11.zoom), m11.panned && (e19.pan = m11.pan)) : e19.zoom = null;
      }
      return new ar4(a8[0], e19);
    };
  }, animate: function() {
    return function(e19, t14) {
      var n11 = this, r8 = void 0 !== n11.length ? n11 : [n11];
      if (!(this._private.cy || this).styleEnabled())
        return this;
      t14 && (e19 = J4({}, e19, t14));
      for (var a8 = 0; a8 < r8.length; a8++) {
        var i9 = r8[a8], o11 = i9.animated() && (void 0 === e19.queue || e19.queue);
        i9.animation(e19, o11 ? { queue: true } : void 0).play();
      }
      return this;
    };
  }, stop: function() {
    return function(e19, t14) {
      var n11 = this, r8 = void 0 !== n11.length ? n11 : [n11], a8 = this._private.cy || this;
      if (!a8.styleEnabled())
        return this;
      for (var i9 = 0; i9 < r8.length; i9++) {
        for (var o11 = r8[i9]._private, s10 = o11.animation.current, l10 = 0; l10 < s10.length; l10++) {
          var u9 = s10[l10]._private;
          t14 && (u9.duration = 0);
        }
        e19 && (o11.animation.queue = []), t14 || (o11.animation.current = []);
      }
      return a8.notify("draw"), this;
    };
  } };
  var sr2 = { data: function(e19) {
    return e19 = J4({}, { field: "data", bindingEvent: "data", allowBinding: false, allowSetting: false, allowGetting: false, settingEvent: "data", settingTriggersEvent: false, triggerFnName: "trigger", immutableKeys: {}, updateStyle: false, beforeGet: function(e20) {
    }, beforeSet: function(e20, t14) {
    }, onSet: function(e20) {
    }, canSet: function(e20) {
      return true;
    } }, e19), function(t14, n11) {
      var r8 = e19, a8 = this, i9 = void 0 !== a8.length, o11 = i9 ? a8 : [a8], s10 = i9 ? a8[0] : a8;
      if (M6(t14)) {
        var l10, u9 = -1 !== t14.indexOf(".") && f6.default(t14);
        if (r8.allowGetting && void 0 === n11)
          return s10 && (r8.beforeGet(s10), l10 = u9 && void 0 === s10._private[r8.field][t14] ? h6.default(s10._private[r8.field], u9) : s10._private[r8.field][t14]), l10;
        if (r8.allowSetting && void 0 !== n11 && !r8.immutableKeys[t14]) {
          var c9 = b6({}, t14, n11);
          r8.beforeSet(a8, c9);
          for (var d10 = 0, g8 = o11.length; d10 < g8; d10++) {
            var v11 = o11[d10];
            r8.canSet(v11) && (u9 && void 0 === s10._private[r8.field][t14] ? p6.default(v11._private[r8.field], u9, n11) : v11._private[r8.field][t14] = n11);
          }
          r8.updateStyle && a8.updateStyle(), r8.onSet(a8), r8.settingTriggersEvent && a8[r8.triggerFnName](r8.settingEvent);
        }
      } else if (r8.allowSetting && N6(t14)) {
        var y9, m11, x10 = t14, w9 = Object.keys(x10);
        r8.beforeSet(a8, x10);
        for (var E8 = 0; E8 < w9.length; E8++) {
          if (m11 = x10[y9 = w9[E8]], !r8.immutableKeys[y9])
            for (var k9 = 0; k9 < o11.length; k9++) {
              var C8 = o11[k9];
              r8.canSet(C8) && (C8._private[r8.field][y9] = m11);
            }
        }
        r8.updateStyle && a8.updateStyle(), r8.onSet(a8), r8.settingTriggersEvent && a8[r8.triggerFnName](r8.settingEvent);
      } else if (r8.allowBinding && B5(t14)) {
        var S7 = t14;
        a8.on(r8.bindingEvent, S7);
      } else if (r8.allowGetting && void 0 === t14) {
        var D7;
        return s10 && (r8.beforeGet(s10), D7 = s10._private[r8.field]), D7;
      }
      return a8;
    };
  }, removeData: function(e19) {
    return e19 = J4({}, { field: "data", event: "data", triggerFnName: "trigger", triggerEvent: false, immutableKeys: {} }, e19), function(t14) {
      var n11 = e19, r8 = this, a8 = void 0 !== r8.length ? r8 : [r8];
      if (M6(t14)) {
        for (var i9 = t14.split(/\s+/), o11 = i9.length, s10 = 0; s10 < o11; s10++) {
          var l10 = i9[s10];
          if (!F5(l10)) {
            if (!n11.immutableKeys[l10])
              for (var u9 = 0, c9 = a8.length; u9 < c9; u9++)
                a8[u9]._private[n11.field][l10] = void 0;
          }
        }
        n11.triggerEvent && r8[n11.triggerFnName](n11.event);
      } else if (void 0 === t14) {
        for (var d10 = 0, h9 = a8.length; d10 < h9; d10++)
          for (var p9 = a8[d10]._private[n11.field], f10 = Object.keys(p9), g8 = 0; g8 < f10.length; g8++) {
            var v11 = f10[g8];
            !n11.immutableKeys[v11] && (p9[v11] = void 0);
          }
        n11.triggerEvent && r8[n11.triggerFnName](n11.event);
      }
      return r8;
    };
  } };
  var lr2 = { eventAliasesOn: function(e19) {
    var t14 = e19;
    t14.addListener = t14.listen = t14.bind = t14.on, t14.unlisten = t14.unbind = t14.off = t14.removeListener, t14.trigger = t14.emit, t14.pon = t14.promiseOn = function(e20, t15) {
      var n11 = this, r8 = Array.prototype.slice.call(arguments, 0);
      return new rr4(function(e21, t16) {
        var a8 = r8.concat([function(t17) {
          n11.off.apply(n11, i9), e21(t17);
        }]), i9 = a8.concat([]);
        n11.on.apply(n11, a8);
      });
    };
  } };
  var ur3 = {};
  [or4, sr2, lr2].forEach(function(e19) {
    J4(ur3, e19);
  });
  var cr3 = { animate: ur3.animate(), animation: ur3.animation(), animated: ur3.animated(), clearQueue: ur3.clearQueue(), delay: ur3.delay(), delayAnimation: ur3.delayAnimation(), stop: ur3.stop() };
  var dr2 = { classes: function(e19) {
    var t14 = this;
    if (void 0 === e19) {
      var n11 = [];
      return t14[0]._private.classes.forEach(function(e20) {
        return n11.push(e20);
      }), n11;
    }
    _5(e19) || (e19 = (e19 || "").match(/\S+/g) || []);
    for (var r8 = [], a8 = new qe(e19), i9 = 0; i9 < t14.length; i9++) {
      for (var o11 = t14[i9], s10 = o11._private, l10 = s10.classes, u9 = false, c9 = 0; c9 < e19.length; c9++) {
        var d10 = e19[c9];
        if (!l10.has(d10)) {
          u9 = true;
          break;
        }
      }
      u9 || (u9 = l10.size !== e19.length), u9 && (s10.classes = a8, r8.push(o11));
    }
    return r8.length > 0 && this.spawn(r8).updateStyle().emit("class"), t14;
  }, addClass: function(e19) {
    return this.toggleClass(e19, true);
  }, hasClass: function(e19) {
    var t14 = this[0];
    return null != t14 && t14._private.classes.has(e19);
  }, toggleClass: function(e19, t14) {
    _5(e19) || (e19 = e19.match(/\S+/g) || []);
    for (var n11 = this, r8 = void 0 === t14, a8 = [], i9 = 0, o11 = n11.length; i9 < o11; i9++)
      for (var s10 = n11[i9], l10 = s10._private.classes, u9 = false, c9 = 0; c9 < e19.length; c9++) {
        var d10 = e19[c9], h9 = l10.has(d10), p9 = false;
        t14 || r8 && !h9 ? (l10.add(d10), p9 = true) : (!t14 || r8 && h9) && (l10.delete(d10), p9 = true), !u9 && p9 && (a8.push(s10), u9 = true);
      }
    return a8.length > 0 && this.spawn(a8).updateStyle().emit("class"), n11;
  }, removeClass: function(e19) {
    return this.toggleClass(e19, false);
  }, flashClass: function(e19, t14) {
    var n11 = this;
    if (null == t14)
      t14 = 250;
    else if (0 === t14)
      return n11;
    return n11.addClass(e19), setTimeout(function() {
      n11.removeClass(e19);
    }, t14), n11;
  } };
  dr2.className = dr2.classNames = dr2.classes;
  var hr2 = { metaChar: "[\\!\\\"\\#\\$\\%\\&\\'\\(\\)\\*\\+\\,\\.\\/\\:\\;\\<\\=\\>\\?\\@\\[\\]\\^\\`\\{\\|\\}\\~]", comparatorOp: "=|\\!=|>|>=|<|<=|\\$=|\\^=|\\*=", boolOp: "\\?|\\!|\\^", string: `"(?:\\\\"|[^"])*"|'(?:\\\\'|[^'])*'`, number: K4, meta: "degree|indegree|outdegree", separator: "\\s*,\\s*", descendant: "\\s+", child: "\\s+>\\s+", subject: "\\$", group: "node|edge|\\*", directedEdge: "\\s+->\\s+", undirectedEdge: "\\s+<->\\s+" };
  hr2.variable = "(?:[\\w-.]|(?:\\\\" + hr2.metaChar + "))+", hr2.className = "(?:[\\w-]|(?:\\\\" + hr2.metaChar + "))+", hr2.value = hr2.string + "|" + hr2.number, hr2.id = hr2.variable, function() {
    var e19, t14, n11;
    for (e19 = hr2.comparatorOp.split("|"), n11 = 0; n11 < e19.length; n11++)
      t14 = e19[n11], hr2.comparatorOp += "|@" + t14;
    for (e19 = hr2.comparatorOp.split("|"), n11 = 0; n11 < e19.length; n11++)
      (t14 = e19[n11]).indexOf("!") >= 0 || "=" !== t14 && (hr2.comparatorOp += "|\\!" + t14);
  }();
  var pr2 = 0;
  var fr2 = 1;
  var gr2 = 2;
  var vr2 = 3;
  var yr2 = 4;
  var mr = 5;
  var br2 = 6;
  var xr = 7;
  var wr = 8;
  var Er = 9;
  var kr = 10;
  var Cr = 11;
  var Sr = 12;
  var Dr = 13;
  var Pr = 14;
  var Tr = 15;
  var Mr = 16;
  var Br = 17;
  var _r2 = 18;
  var Nr = 19;
  var Ir = 20;
  var zr = [{ selector: ":selected", matches: function(e19) {
    return e19.selected();
  } }, { selector: ":unselected", matches: function(e19) {
    return !e19.selected();
  } }, { selector: ":selectable", matches: function(e19) {
    return e19.selectable();
  } }, { selector: ":unselectable", matches: function(e19) {
    return !e19.selectable();
  } }, { selector: ":locked", matches: function(e19) {
    return e19.locked();
  } }, { selector: ":unlocked", matches: function(e19) {
    return !e19.locked();
  } }, { selector: ":visible", matches: function(e19) {
    return e19.visible();
  } }, { selector: ":hidden", matches: function(e19) {
    return !e19.visible();
  } }, { selector: ":transparent", matches: function(e19) {
    return e19.transparent();
  } }, { selector: ":grabbed", matches: function(e19) {
    return e19.grabbed();
  } }, { selector: ":free", matches: function(e19) {
    return !e19.grabbed();
  } }, { selector: ":removed", matches: function(e19) {
    return e19.removed();
  } }, { selector: ":inside", matches: function(e19) {
    return !e19.removed();
  } }, { selector: ":grabbable", matches: function(e19) {
    return e19.grabbable();
  } }, { selector: ":ungrabbable", matches: function(e19) {
    return !e19.grabbable();
  } }, { selector: ":animated", matches: function(e19) {
    return e19.animated();
  } }, { selector: ":unanimated", matches: function(e19) {
    return !e19.animated();
  } }, { selector: ":parent", matches: function(e19) {
    return e19.isParent();
  } }, { selector: ":childless", matches: function(e19) {
    return e19.isChildless();
  } }, { selector: ":child", matches: function(e19) {
    return e19.isChild();
  } }, { selector: ":orphan", matches: function(e19) {
    return e19.isOrphan();
  } }, { selector: ":nonorphan", matches: function(e19) {
    return e19.isChild();
  } }, { selector: ":compound", matches: function(e19) {
    return e19.isNode() ? e19.isParent() : e19.source().isParent() || e19.target().isParent();
  } }, { selector: ":loop", matches: function(e19) {
    return e19.isLoop();
  } }, { selector: ":simple", matches: function(e19) {
    return e19.isSimple();
  } }, { selector: ":active", matches: function(e19) {
    return e19.active();
  } }, { selector: ":inactive", matches: function(e19) {
    return !e19.active();
  } }, { selector: ":backgrounding", matches: function(e19) {
    return e19.backgrounding();
  } }, { selector: ":nonbackgrounding", matches: function(e19) {
    return !e19.backgrounding();
  } }].sort(function(e19, t14) {
    return function(e20, t15) {
      return -1 * Q4(e20, t15);
    }(e19.selector, t14.selector);
  });
  var Lr = function() {
    for (var e19, t14 = {}, n11 = 0; n11 < zr.length; n11++)
      t14[(e19 = zr[n11]).selector] = e19.matches;
    return t14;
  }();
  var Ar = "(" + zr.map(function(e19) {
    return e19.selector;
  }).join("|") + ")";
  var Or = function(e19) {
    return e19.replace(new RegExp("\\\\(" + hr2.metaChar + ")", "g"), function(e20, t14) {
      return t14;
    });
  };
  var Rr = function(e19, t14, n11) {
    e19[e19.length - 1] = n11;
  };
  var Vr = [{ name: "group", query: true, regex: "(" + hr2.group + ")", populate: function(e19, t14, n11) {
    var r8 = x6(n11, 1)[0];
    t14.checks.push({ type: pr2, value: "*" === r8 ? r8 : r8 + "s" });
  } }, { name: "state", query: true, regex: Ar, populate: function(e19, t14, n11) {
    var r8 = x6(n11, 1)[0];
    t14.checks.push({ type: xr, value: r8 });
  } }, { name: "id", query: true, regex: "\\#(" + hr2.id + ")", populate: function(e19, t14, n11) {
    var r8 = x6(n11, 1)[0];
    t14.checks.push({ type: wr, value: Or(r8) });
  } }, { name: "className", query: true, regex: "\\.(" + hr2.className + ")", populate: function(e19, t14, n11) {
    var r8 = x6(n11, 1)[0];
    t14.checks.push({ type: Er, value: Or(r8) });
  } }, { name: "dataExists", query: true, regex: "\\[\\s*(" + hr2.variable + ")\\s*\\]", populate: function(e19, t14, n11) {
    var r8 = x6(n11, 1)[0];
    t14.checks.push({ type: yr2, field: Or(r8) });
  } }, { name: "dataCompare", query: true, regex: "\\[\\s*(" + hr2.variable + ")\\s*(" + hr2.comparatorOp + ")\\s*(" + hr2.value + ")\\s*\\]", populate: function(e19, t14, n11) {
    var r8 = x6(n11, 3), a8 = r8[0], i9 = r8[1], o11 = r8[2];
    o11 = null != new RegExp("^" + hr2.string + "$").exec(o11) ? o11.substring(1, o11.length - 1) : parseFloat(o11), t14.checks.push({ type: vr2, field: Or(a8), operator: i9, value: o11 });
  } }, { name: "dataBool", query: true, regex: "\\[\\s*(" + hr2.boolOp + ")\\s*(" + hr2.variable + ")\\s*\\]", populate: function(e19, t14, n11) {
    var r8 = x6(n11, 2), a8 = r8[0], i9 = r8[1];
    t14.checks.push({ type: mr, field: Or(i9), operator: a8 });
  } }, { name: "metaCompare", query: true, regex: "\\[\\[\\s*(" + hr2.meta + ")\\s*(" + hr2.comparatorOp + ")\\s*(" + hr2.number + ")\\s*\\]\\]", populate: function(e19, t14, n11) {
    var r8 = x6(n11, 3), a8 = r8[0], i9 = r8[1], o11 = r8[2];
    t14.checks.push({ type: br2, field: Or(a8), operator: i9, value: parseFloat(o11) });
  } }, { name: "nextQuery", separator: true, regex: hr2.separator, populate: function(e19, t14) {
    var n11 = e19.currentSubject, r8 = e19.edgeCount, a8 = e19.compoundCount, i9 = e19[e19.length - 1];
    return null != n11 && (i9.subject = n11, e19.currentSubject = null), i9.edgeCount = r8, i9.compoundCount = a8, e19.edgeCount = 0, e19.compoundCount = 0, e19[e19.length++] = { checks: [] };
  } }, { name: "directedEdge", separator: true, regex: hr2.directedEdge, populate: function(e19, t14) {
    if (null == e19.currentSubject) {
      var n11 = { checks: [] }, r8 = t14, a8 = { checks: [] };
      return n11.checks.push({ type: Cr, source: r8, target: a8 }), Rr(e19, 0, n11), e19.edgeCount++, a8;
    }
    var i9 = { checks: [] }, o11 = t14, s10 = { checks: [] };
    return i9.checks.push({ type: Sr, source: o11, target: s10 }), Rr(e19, 0, i9), e19.edgeCount++, s10;
  } }, { name: "undirectedEdge", separator: true, regex: hr2.undirectedEdge, populate: function(e19, t14) {
    if (null == e19.currentSubject) {
      var n11 = { checks: [] }, r8 = t14, a8 = { checks: [] };
      return n11.checks.push({ type: kr, nodes: [r8, a8] }), Rr(e19, 0, n11), e19.edgeCount++, a8;
    }
    var i9 = { checks: [] }, o11 = t14, s10 = { checks: [] };
    return i9.checks.push({ type: Pr, node: o11, neighbor: s10 }), Rr(e19, 0, i9), s10;
  } }, { name: "child", separator: true, regex: hr2.child, populate: function(e19, t14) {
    if (null == e19.currentSubject) {
      var n11 = { checks: [] }, r8 = { checks: [] }, a8 = e19[e19.length - 1];
      return n11.checks.push({ type: Tr, parent: a8, child: r8 }), Rr(e19, 0, n11), e19.compoundCount++, r8;
    }
    if (e19.currentSubject === t14) {
      var i9 = { checks: [] }, o11 = e19[e19.length - 1], s10 = { checks: [] }, l10 = { checks: [] }, u9 = { checks: [] }, c9 = { checks: [] };
      return i9.checks.push({ type: Nr, left: o11, right: s10, subject: l10 }), l10.checks = t14.checks, t14.checks = [{ type: Ir }], c9.checks.push({ type: Ir }), s10.checks.push({ type: Br, parent: c9, child: u9 }), Rr(e19, 0, i9), e19.currentSubject = l10, e19.compoundCount++, u9;
    }
    var d10 = { checks: [] }, h9 = { checks: [] }, p9 = [{ type: Br, parent: d10, child: h9 }];
    return d10.checks = t14.checks, t14.checks = p9, e19.compoundCount++, h9;
  } }, { name: "descendant", separator: true, regex: hr2.descendant, populate: function(e19, t14) {
    if (null == e19.currentSubject) {
      var n11 = { checks: [] }, r8 = { checks: [] }, a8 = e19[e19.length - 1];
      return n11.checks.push({ type: Mr, ancestor: a8, descendant: r8 }), Rr(e19, 0, n11), e19.compoundCount++, r8;
    }
    if (e19.currentSubject === t14) {
      var i9 = { checks: [] }, o11 = e19[e19.length - 1], s10 = { checks: [] }, l10 = { checks: [] }, u9 = { checks: [] }, c9 = { checks: [] };
      return i9.checks.push({ type: Nr, left: o11, right: s10, subject: l10 }), l10.checks = t14.checks, t14.checks = [{ type: Ir }], c9.checks.push({ type: Ir }), s10.checks.push({ type: _r2, ancestor: c9, descendant: u9 }), Rr(e19, 0, i9), e19.currentSubject = l10, e19.compoundCount++, u9;
    }
    var d10 = { checks: [] }, h9 = { checks: [] }, p9 = [{ type: _r2, ancestor: d10, descendant: h9 }];
    return d10.checks = t14.checks, t14.checks = p9, e19.compoundCount++, h9;
  } }, { name: "subject", modifier: true, regex: hr2.subject, populate: function(e19, t14) {
    if (null != e19.currentSubject && e19.currentSubject !== t14)
      return Me("Redefinition of subject in selector `" + e19.toString() + "`"), false;
    e19.currentSubject = t14;
    var n11 = e19[e19.length - 1].checks[0], r8 = null == n11 ? null : n11.type;
    r8 === Cr ? n11.type = Dr : r8 === kr && (n11.type = Pr, n11.node = n11.nodes[1], n11.neighbor = n11.nodes[0], n11.nodes = null);
  } }];
  Vr.forEach(function(e19) {
    return e19.regexObj = new RegExp("^" + e19.regex);
  });
  var Fr = function(e19) {
    for (var t14, n11, r8, a8 = 0; a8 < Vr.length; a8++) {
      var i9 = Vr[a8], o11 = i9.name, s10 = e19.match(i9.regexObj);
      if (null != s10) {
        n11 = s10, t14 = i9, r8 = o11;
        var l10 = s10[0];
        e19 = e19.substring(l10.length);
        break;
      }
    }
    return { expr: t14, match: n11, name: r8, remaining: e19 };
  };
  var qr = { parse: function(e19) {
    var t14 = this, n11 = t14.inputText = e19, r8 = t14[0] = { checks: [] };
    for (t14.length = 1, n11 = function(e20) {
      var t15 = e20.match(/^\s+/);
      if (t15) {
        var n12 = t15[0];
        e20 = e20.substring(n12.length);
      }
      return e20;
    }(n11); ; ) {
      var a8 = Fr(n11);
      if (null == a8.expr)
        return Me("The selector `" + e19 + "`is invalid"), false;
      var i9 = a8.match.slice(1), o11 = a8.expr.populate(t14, r8, i9);
      if (false === o11)
        return false;
      if (null != o11 && (r8 = o11), (n11 = a8.remaining).match(/^\s*$/))
        break;
    }
    var s10 = t14[t14.length - 1];
    null != t14.currentSubject && (s10.subject = t14.currentSubject), s10.edgeCount = t14.edgeCount, s10.compoundCount = t14.compoundCount;
    for (var l10 = 0; l10 < t14.length; l10++) {
      var u9 = t14[l10];
      if (u9.compoundCount > 0 && u9.edgeCount > 0)
        return Me("The selector `" + e19 + "` is invalid because it uses both a compound selector and an edge selector"), false;
      if (u9.edgeCount > 1)
        return Me("The selector `" + e19 + "` is invalid because it uses multiple edge selectors"), false;
      1 === u9.edgeCount && Me("The selector `" + e19 + "` is deprecated.  Edge selectors do not take effect on changes to source and target nodes after an edge is added, for performance reasons.  Use a class or data selector on edges instead, updating the class or data of an edge when your app detects a change in source or target nodes.");
    }
    return true;
  }, toString: function() {
    if (null != this.toStringCache)
      return this.toStringCache;
    for (var e19 = function(e20) {
      return null == e20 ? "" : e20;
    }, t14 = function(t15) {
      return M6(t15) ? '"' + t15 + '"' : e19(t15);
    }, n11 = function(e20) {
      return " " + e20 + " ";
    }, r8 = function(r9, i10) {
      var o12 = r9.type, s11 = r9.value;
      switch (o12) {
        case pr2:
          var l10 = e19(s11);
          return l10.substring(0, l10.length - 1);
        case vr2:
          var u9 = r9.field, c9 = r9.operator;
          return "[" + u9 + n11(e19(c9)) + t14(s11) + "]";
        case mr:
          var d10 = r9.operator, h9 = r9.field;
          return "[" + e19(d10) + h9 + "]";
        case yr2:
          return "[" + r9.field + "]";
        case br2:
          var p9 = r9.operator;
          return "[[" + r9.field + n11(e19(p9)) + t14(s11) + "]]";
        case xr:
          return s11;
        case wr:
          return "#" + s11;
        case Er:
          return "." + s11;
        case Br:
        case Tr:
          return a8(r9.parent, i10) + n11(">") + a8(r9.child, i10);
        case _r2:
        case Mr:
          return a8(r9.ancestor, i10) + " " + a8(r9.descendant, i10);
        case Nr:
          var f10 = a8(r9.left, i10), g8 = a8(r9.subject, i10), v11 = a8(r9.right, i10);
          return f10 + (f10.length > 0 ? " " : "") + g8 + v11;
        case Ir:
          return "";
      }
    }, a8 = function(e20, t15) {
      return e20.checks.reduce(function(n12, a9, i10) {
        return n12 + (t15 === e20 && 0 === i10 ? "$" : "") + r8(a9, t15);
      }, "");
    }, i9 = "", o11 = 0; o11 < this.length; o11++) {
      var s10 = this[o11];
      i9 += a8(s10, s10.subject), this.length > 1 && o11 < this.length - 1 && (i9 += ", ");
    }
    return this.toStringCache = i9, i9;
  } };
  var jr = function(e19, t14, n11) {
    var r8, a8, i9, o11 = M6(e19), s10 = I6(e19), l10 = M6(n11), u9 = false, c9 = false, d10 = false;
    switch (t14.indexOf("!") >= 0 && (t14 = t14.replace("!", ""), c9 = true), t14.indexOf("@") >= 0 && (t14 = t14.replace("@", ""), u9 = true), (o11 || l10 || u9) && (a8 = o11 || s10 ? "" + e19 : "", i9 = "" + n11), u9 && (e19 = a8 = a8.toLowerCase(), n11 = i9 = i9.toLowerCase()), t14) {
      case "*=":
        r8 = a8.indexOf(i9) >= 0;
        break;
      case "$=":
        r8 = a8.indexOf(i9, a8.length - i9.length) >= 0;
        break;
      case "^=":
        r8 = 0 === a8.indexOf(i9);
        break;
      case "=":
        r8 = e19 === n11;
        break;
      case ">":
        d10 = true, r8 = e19 > n11;
        break;
      case ">=":
        d10 = true, r8 = e19 >= n11;
        break;
      case "<":
        d10 = true, r8 = e19 < n11;
        break;
      case "<=":
        d10 = true, r8 = e19 <= n11;
        break;
      default:
        r8 = false;
    }
    return !c9 || null == e19 && d10 || (r8 = !r8), r8;
  };
  var Yr = function(e19, t14) {
    return e19.data(t14);
  };
  var Xr = [];
  var Wr = function(e19, t14) {
    return e19.checks.every(function(e20) {
      return Xr[e20.type](e20, t14);
    });
  };
  Xr[pr2] = function(e19, t14) {
    var n11 = e19.value;
    return "*" === n11 || n11 === t14.group();
  }, Xr[xr] = function(e19, t14) {
    return function(e20, t15) {
      return Lr[e20](t15);
    }(e19.value, t14);
  }, Xr[wr] = function(e19, t14) {
    var n11 = e19.value;
    return t14.id() === n11;
  }, Xr[Er] = function(e19, t14) {
    var n11 = e19.value;
    return t14.hasClass(n11);
  }, Xr[br2] = function(e19, t14) {
    var n11 = e19.field, r8 = e19.operator, a8 = e19.value;
    return jr(function(e20, t15) {
      return e20[t15]();
    }(t14, n11), r8, a8);
  }, Xr[vr2] = function(e19, t14) {
    var n11 = e19.field, r8 = e19.operator, a8 = e19.value;
    return jr(Yr(t14, n11), r8, a8);
  }, Xr[mr] = function(e19, t14) {
    var n11 = e19.field, r8 = e19.operator;
    return function(e20, t15) {
      switch (t15) {
        case "?":
          return !!e20;
        case "!":
          return !e20;
        case "^":
          return void 0 === e20;
      }
    }(Yr(t14, n11), r8);
  }, Xr[yr2] = function(e19, t14) {
    var n11 = e19.field;
    return e19.operator, void 0 !== Yr(t14, n11);
  }, Xr[kr] = function(e19, t14) {
    var n11 = e19.nodes[0], r8 = e19.nodes[1], a8 = t14.source(), i9 = t14.target();
    return Wr(n11, a8) && Wr(r8, i9) || Wr(r8, a8) && Wr(n11, i9);
  }, Xr[Pr] = function(e19, t14) {
    return Wr(e19.node, t14) && t14.neighborhood().some(function(t15) {
      return t15.isNode() && Wr(e19.neighbor, t15);
    });
  }, Xr[Cr] = function(e19, t14) {
    return Wr(e19.source, t14.source()) && Wr(e19.target, t14.target());
  }, Xr[Sr] = function(e19, t14) {
    return Wr(e19.source, t14) && t14.outgoers().some(function(t15) {
      return t15.isNode() && Wr(e19.target, t15);
    });
  }, Xr[Dr] = function(e19, t14) {
    return Wr(e19.target, t14) && t14.incomers().some(function(t15) {
      return t15.isNode() && Wr(e19.source, t15);
    });
  }, Xr[Tr] = function(e19, t14) {
    return Wr(e19.child, t14) && Wr(e19.parent, t14.parent());
  }, Xr[Br] = function(e19, t14) {
    return Wr(e19.parent, t14) && t14.children().some(function(t15) {
      return Wr(e19.child, t15);
    });
  }, Xr[Mr] = function(e19, t14) {
    return Wr(e19.descendant, t14) && t14.ancestors().some(function(t15) {
      return Wr(e19.ancestor, t15);
    });
  }, Xr[_r2] = function(e19, t14) {
    return Wr(e19.ancestor, t14) && t14.descendants().some(function(t15) {
      return Wr(e19.descendant, t15);
    });
  }, Xr[Nr] = function(e19, t14) {
    return Wr(e19.subject, t14) && Wr(e19.left, t14) && Wr(e19.right, t14);
  }, Xr[Ir] = function() {
    return true;
  }, Xr[fr2] = function(e19, t14) {
    return e19.value.has(t14);
  }, Xr[gr2] = function(e19, t14) {
    return (0, e19.value)(t14);
  };
  var Hr = { matches: function(e19) {
    for (var t14 = 0; t14 < this.length; t14++) {
      var n11 = this[t14];
      if (Wr(n11, e19))
        return true;
    }
    return false;
  }, filter: function(e19) {
    var t14 = this;
    if (1 === t14.length && 1 === t14[0].checks.length && t14[0].checks[0].type === wr)
      return e19.getElementById(t14[0].checks[0].value).collection();
    var n11 = function(e20) {
      for (var n12 = 0; n12 < t14.length; n12++) {
        var r8 = t14[n12];
        if (Wr(r8, e20))
          return true;
      }
      return false;
    };
    return null == t14.text() && (n11 = function() {
      return true;
    }), e19.filter(n11);
  } };
  var Kr = function(e19) {
    this.inputText = e19, this.currentSubject = null, this.compoundCount = 0, this.edgeCount = 0, this.length = 0, null == e19 || M6(e19) && e19.match(/^\s*$/) || (L5(e19) ? this.addQuery({ checks: [{ type: fr2, value: e19.collection() }] }) : B5(e19) ? this.addQuery({ checks: [{ type: gr2, value: e19 }] }) : M6(e19) ? this.parse(e19) || (this.invalid = true) : Pe("A selector must be created from a string; found "));
  };
  var Gr = Kr.prototype;
  [qr, Hr].forEach(function(e19) {
    return J4(Gr, e19);
  }), Gr.text = function() {
    return this.inputText;
  }, Gr.size = function() {
    return this.length;
  }, Gr.eq = function(e19) {
    return this[e19];
  }, Gr.sameText = function(e19) {
    return !this.invalid && !e19.invalid && this.text() === e19.text();
  }, Gr.addQuery = function(e19) {
    this[this.length++] = e19;
  }, Gr.selector = Gr.toString;
  var Ur = { allAre: function(e19) {
    var t14 = new Kr(e19);
    return this.every(function(e20) {
      return t14.matches(e20);
    });
  }, is: function(e19) {
    var t14 = new Kr(e19);
    return this.some(function(e20) {
      return t14.matches(e20);
    });
  }, some: function(e19, t14) {
    for (var n11 = 0; n11 < this.length; n11++) {
      if (t14 ? e19.apply(t14, [this[n11], n11, this]) : e19(this[n11], n11, this))
        return true;
    }
    return false;
  }, every: function(e19, t14) {
    for (var n11 = 0; n11 < this.length; n11++) {
      if (!(t14 ? e19.apply(t14, [this[n11], n11, this]) : e19(this[n11], n11, this)))
        return false;
    }
    return true;
  }, same: function(e19) {
    if (this === e19)
      return true;
    e19 = this.cy().collection(e19);
    var t14 = this.length;
    return t14 === e19.length && (1 === t14 ? this[0] === e19[0] : this.every(function(t15) {
      return e19.hasElementWithId(t15.id());
    }));
  }, anySame: function(e19) {
    return e19 = this.cy().collection(e19), this.some(function(t14) {
      return e19.hasElementWithId(t14.id());
    });
  }, allAreNeighbors: function(e19) {
    e19 = this.cy().collection(e19);
    var t14 = this.neighborhood();
    return e19.every(function(e20) {
      return t14.hasElementWithId(e20.id());
    });
  }, contains: function(e19) {
    e19 = this.cy().collection(e19);
    var t14 = this;
    return e19.every(function(e20) {
      return t14.hasElementWithId(e20.id());
    });
  } };
  Ur.allAreNeighbours = Ur.allAreNeighbors, Ur.has = Ur.contains, Ur.equal = Ur.equals = Ur.same;
  var Zr;
  var $r;
  var Qr = function(e19, t14) {
    return function(n11, r8, a8, i9) {
      var o11, s10 = n11, l10 = this;
      if (null == s10 ? o11 = "" : L5(s10) && 1 === s10.length && (o11 = s10.id()), 1 === l10.length && o11) {
        var u9 = l10[0]._private, c9 = u9.traversalCache = u9.traversalCache || {}, d10 = c9[t14] = c9[t14] || [], h9 = ve(o11), p9 = d10[h9];
        return p9 || (d10[h9] = e19.call(l10, n11, r8, a8, i9));
      }
      return e19.call(l10, n11, r8, a8, i9);
    };
  };
  var Jr = { parent: function(e19) {
    var t14 = [];
    if (1 === this.length) {
      var n11 = this[0]._private.parent;
      if (n11)
        return n11;
    }
    for (var r8 = 0; r8 < this.length; r8++) {
      var a8 = this[r8]._private.parent;
      a8 && t14.push(a8);
    }
    return this.spawn(t14, true).filter(e19);
  }, parents: function(e19) {
    for (var t14 = [], n11 = this.parent(); n11.nonempty(); ) {
      for (var r8 = 0; r8 < n11.length; r8++) {
        var a8 = n11[r8];
        t14.push(a8);
      }
      n11 = n11.parent();
    }
    return this.spawn(t14, true).filter(e19);
  }, commonAncestors: function(e19) {
    for (var t14, n11 = 0; n11 < this.length; n11++) {
      var r8 = this[n11].parents();
      t14 = (t14 = t14 || r8).intersect(r8);
    }
    return t14.filter(e19);
  }, orphans: function(e19) {
    return this.stdFilter(function(e20) {
      return e20.isOrphan();
    }).filter(e19);
  }, nonorphans: function(e19) {
    return this.stdFilter(function(e20) {
      return e20.isChild();
    }).filter(e19);
  }, children: Qr(function(e19) {
    for (var t14 = [], n11 = 0; n11 < this.length; n11++)
      for (var r8 = this[n11]._private.children, a8 = 0; a8 < r8.length; a8++)
        t14.push(r8[a8]);
    return this.spawn(t14, true).filter(e19);
  }, "children"), siblings: function(e19) {
    return this.parent().children().not(this).filter(e19);
  }, isParent: function() {
    var e19 = this[0];
    if (e19)
      return e19.isNode() && 0 !== e19._private.children.length;
  }, isChildless: function() {
    var e19 = this[0];
    if (e19)
      return e19.isNode() && 0 === e19._private.children.length;
  }, isChild: function() {
    var e19 = this[0];
    if (e19)
      return e19.isNode() && null != e19._private.parent;
  }, isOrphan: function() {
    var e19 = this[0];
    if (e19)
      return e19.isNode() && null == e19._private.parent;
  }, descendants: function(e19) {
    var t14 = [];
    return function e20(n11) {
      for (var r8 = 0; r8 < n11.length; r8++) {
        var a8 = n11[r8];
        t14.push(a8), a8.children().nonempty() && e20(a8.children());
      }
    }(this.children()), this.spawn(t14, true).filter(e19);
  } };
  function ea(e19, t14, n11, r8) {
    for (var a8 = [], i9 = new qe(), o11 = e19.cy().hasCompoundNodes(), s10 = 0; s10 < e19.length; s10++) {
      var l10 = e19[s10];
      n11 ? a8.push(l10) : o11 && r8(a8, i9, l10);
    }
    for (; a8.length > 0; ) {
      var u9 = a8.shift();
      t14(u9), i9.add(u9.id()), o11 && r8(a8, i9, u9);
    }
    return e19;
  }
  function ta(e19, t14, n11) {
    if (n11.isParent())
      for (var r8 = n11._private.children, a8 = 0; a8 < r8.length; a8++) {
        var i9 = r8[a8];
        t14.has(i9.id()) || e19.push(i9);
      }
  }
  function na(e19, t14, n11) {
    if (n11.isChild()) {
      var r8 = n11._private.parent;
      t14.has(r8.id()) || e19.push(r8);
    }
  }
  function ra(e19, t14, n11) {
    na(e19, t14, n11), ta(e19, t14, n11);
  }
  Jr.forEachDown = function(e19) {
    return ea(this, e19, !(arguments.length > 1 && void 0 !== arguments[1]) || arguments[1], ta);
  }, Jr.forEachUp = function(e19) {
    return ea(this, e19, !(arguments.length > 1 && void 0 !== arguments[1]) || arguments[1], na);
  }, Jr.forEachUpAndDown = function(e19) {
    return ea(this, e19, !(arguments.length > 1 && void 0 !== arguments[1]) || arguments[1], ra);
  }, Jr.ancestors = Jr.parents, (Zr = $r = { data: ur3.data({ field: "data", bindingEvent: "data", allowBinding: true, allowSetting: true, settingEvent: "data", settingTriggersEvent: true, triggerFnName: "trigger", allowGetting: true, immutableKeys: { id: true, source: true, target: true, parent: true }, updateStyle: true }), removeData: ur3.removeData({ field: "data", event: "data", triggerFnName: "trigger", triggerEvent: true, immutableKeys: { id: true, source: true, target: true, parent: true }, updateStyle: true }), scratch: ur3.data({ field: "scratch", bindingEvent: "scratch", allowBinding: true, allowSetting: true, settingEvent: "scratch", settingTriggersEvent: true, triggerFnName: "trigger", allowGetting: true, updateStyle: true }), removeScratch: ur3.removeData({ field: "scratch", event: "scratch", triggerFnName: "trigger", triggerEvent: true, updateStyle: true }), rscratch: ur3.data({ field: "rscratch", allowBinding: false, allowSetting: true, settingTriggersEvent: false, allowGetting: true }), removeRscratch: ur3.removeData({ field: "rscratch", triggerEvent: false }), id: function() {
    var e19 = this[0];
    if (e19)
      return e19._private.data.id;
  } }).attr = Zr.data, Zr.removeAttr = Zr.removeData;
  var aa;
  var ia;
  var oa = $r;
  var sa = {};
  function la(e19) {
    return function(t14) {
      var n11 = this;
      if (void 0 === t14 && (t14 = true), 0 !== n11.length && n11.isNode() && !n11.removed()) {
        for (var r8 = 0, a8 = n11[0], i9 = a8._private.edges, o11 = 0; o11 < i9.length; o11++) {
          var s10 = i9[o11];
          !t14 && s10.isLoop() || (r8 += e19(a8, s10));
        }
        return r8;
      }
    };
  }
  function ua(e19, t14) {
    return function(n11) {
      for (var r8, a8 = this.nodes(), i9 = 0; i9 < a8.length; i9++) {
        var o11 = a8[i9][e19](n11);
        void 0 === o11 || void 0 !== r8 && !t14(o11, r8) || (r8 = o11);
      }
      return r8;
    };
  }
  J4(sa, { degree: la(function(e19, t14) {
    return t14.source().same(t14.target()) ? 2 : 1;
  }), indegree: la(function(e19, t14) {
    return t14.target().same(e19) ? 1 : 0;
  }), outdegree: la(function(e19, t14) {
    return t14.source().same(e19) ? 1 : 0;
  }) }), J4(sa, { minDegree: ua("degree", function(e19, t14) {
    return e19 < t14;
  }), maxDegree: ua("degree", function(e19, t14) {
    return e19 > t14;
  }), minIndegree: ua("indegree", function(e19, t14) {
    return e19 < t14;
  }), maxIndegree: ua("indegree", function(e19, t14) {
    return e19 > t14;
  }), minOutdegree: ua("outdegree", function(e19, t14) {
    return e19 < t14;
  }), maxOutdegree: ua("outdegree", function(e19, t14) {
    return e19 > t14;
  }) }), J4(sa, { totalDegree: function(e19) {
    for (var t14 = 0, n11 = this.nodes(), r8 = 0; r8 < n11.length; r8++)
      t14 += n11[r8].degree(e19);
    return t14;
  } });
  var ca = function(e19, t14, n11) {
    for (var r8 = 0; r8 < e19.length; r8++) {
      var a8 = e19[r8];
      if (!a8.locked()) {
        var i9 = a8._private.position, o11 = { x: null != t14.x ? t14.x - i9.x : 0, y: null != t14.y ? t14.y - i9.y : 0 };
        !a8.isParent() || 0 === o11.x && 0 === o11.y || a8.children().shift(o11, n11), a8.dirtyBoundingBoxCache();
      }
    }
  };
  var da = { field: "position", bindingEvent: "position", allowBinding: true, allowSetting: true, settingEvent: "position", settingTriggersEvent: true, triggerFnName: "emitAndNotify", allowGetting: true, validKeys: ["x", "y"], beforeGet: function(e19) {
    e19.updateCompoundBounds();
  }, beforeSet: function(e19, t14) {
    ca(e19, t14, false);
  }, onSet: function(e19) {
    e19.dirtyCompoundBoundsCache();
  }, canSet: function(e19) {
    return !e19.locked();
  } };
  aa = ia = { position: ur3.data(da), silentPosition: ur3.data(J4({}, da, { allowBinding: false, allowSetting: true, settingTriggersEvent: false, allowGetting: false, beforeSet: function(e19, t14) {
    ca(e19, t14, true);
  }, onSet: function(e19) {
    e19.dirtyCompoundBoundsCache();
  } })), positions: function(e19, t14) {
    if (N6(e19))
      t14 ? this.silentPosition(e19) : this.position(e19);
    else if (B5(e19)) {
      var n11 = e19, r8 = this.cy();
      r8.startBatch();
      for (var a8 = 0; a8 < this.length; a8++) {
        var i9, o11 = this[a8];
        (i9 = n11(o11, a8)) && (t14 ? o11.silentPosition(i9) : o11.position(i9));
      }
      r8.endBatch();
    }
    return this;
  }, silentPositions: function(e19) {
    return this.positions(e19, true);
  }, shift: function(e19, t14, n11) {
    var r8;
    if (N6(e19) ? (r8 = { x: I6(e19.x) ? e19.x : 0, y: I6(e19.y) ? e19.y : 0 }, n11 = t14) : M6(e19) && I6(t14) && ((r8 = { x: 0, y: 0 })[e19] = t14), null != r8) {
      var a8 = this.cy();
      a8.startBatch();
      for (var i9 = 0; i9 < this.length; i9++) {
        var o11 = this[i9];
        if (!(a8.hasCompoundNodes() && o11.isChild() && o11.ancestors().anySame(this))) {
          var s10 = o11.position(), l10 = { x: s10.x + r8.x, y: s10.y + r8.y };
          n11 ? o11.silentPosition(l10) : o11.position(l10);
        }
      }
      a8.endBatch();
    }
    return this;
  }, silentShift: function(e19, t14) {
    return N6(e19) ? this.shift(e19, true) : M6(e19) && I6(t14) && this.shift(e19, t14, true), this;
  }, renderedPosition: function(e19, t14) {
    var n11 = this[0], r8 = this.cy(), a8 = r8.zoom(), i9 = r8.pan(), o11 = N6(e19) ? e19 : void 0, s10 = void 0 !== o11 || void 0 !== t14 && M6(e19);
    if (n11 && n11.isNode()) {
      if (!s10) {
        var l10 = n11.position();
        return o11 = at4(l10, a8, i9), void 0 === e19 ? o11 : o11[e19];
      }
      for (var u9 = 0; u9 < this.length; u9++) {
        var c9 = this[u9];
        void 0 !== t14 ? c9.position(e19, (t14 - i9[e19]) / a8) : void 0 !== o11 && c9.position(it4(o11, a8, i9));
      }
    } else if (!s10)
      return;
    return this;
  }, relativePosition: function(e19, t14) {
    var n11 = this[0], r8 = this.cy(), a8 = N6(e19) ? e19 : void 0, i9 = void 0 !== a8 || void 0 !== t14 && M6(e19), o11 = r8.hasCompoundNodes();
    if (n11 && n11.isNode()) {
      if (!i9) {
        var s10 = n11.position(), l10 = o11 ? n11.parent() : null, u9 = l10 && l10.length > 0, c9 = u9;
        u9 && (l10 = l10[0]);
        var d10 = c9 ? l10.position() : { x: 0, y: 0 };
        return a8 = { x: s10.x - d10.x, y: s10.y - d10.y }, void 0 === e19 ? a8 : a8[e19];
      }
      for (var h9 = 0; h9 < this.length; h9++) {
        var p9 = this[h9], f10 = o11 ? p9.parent() : null, g8 = f10 && f10.length > 0, v11 = g8;
        g8 && (f10 = f10[0]);
        var y9 = v11 ? f10.position() : { x: 0, y: 0 };
        void 0 !== t14 ? p9.position(e19, t14 + y9[e19]) : void 0 !== a8 && p9.position({ x: a8.x + y9.x, y: a8.y + y9.y });
      }
    } else if (!i9)
      return;
    return this;
  } }, aa.modelPosition = aa.point = aa.position, aa.modelPositions = aa.points = aa.positions, aa.renderedPoint = aa.renderedPosition, aa.relativePoint = aa.relativePosition;
  var ha;
  var pa;
  var fa = ia;
  ha = pa = {}, pa.renderedBoundingBox = function(e19) {
    var t14 = this.boundingBox(e19), n11 = this.cy(), r8 = n11.zoom(), a8 = n11.pan(), i9 = t14.x1 * r8 + a8.x, o11 = t14.x2 * r8 + a8.x, s10 = t14.y1 * r8 + a8.y, l10 = t14.y2 * r8 + a8.y;
    return { x1: i9, x2: o11, y1: s10, y2: l10, w: o11 - i9, h: l10 - s10 };
  }, pa.dirtyCompoundBoundsCache = function() {
    var e19 = arguments.length > 0 && void 0 !== arguments[0] && arguments[0], t14 = this.cy();
    return t14.styleEnabled() && t14.hasCompoundNodes() ? (this.forEachUp(function(t15) {
      if (t15.isParent()) {
        var n11 = t15._private;
        n11.compoundBoundsClean = false, n11.bbCache = null, e19 || t15.emitAndNotify("bounds");
      }
    }), this) : this;
  }, pa.updateCompoundBounds = function() {
    var e19 = arguments.length > 0 && void 0 !== arguments[0] && arguments[0], t14 = this.cy();
    if (!t14.styleEnabled() || !t14.hasCompoundNodes())
      return this;
    if (!e19 && t14.batching())
      return this;
    function n11(e20) {
      if (e20.isParent()) {
        var t15 = e20._private, n12 = e20.children(), r9 = "include" === e20.pstyle("compound-sizing-wrt-labels").value, a9 = { width: { val: e20.pstyle("min-width").pfValue, left: e20.pstyle("min-width-bias-left"), right: e20.pstyle("min-width-bias-right") }, height: { val: e20.pstyle("min-height").pfValue, top: e20.pstyle("min-height-bias-top"), bottom: e20.pstyle("min-height-bias-bottom") } }, i10 = n12.boundingBox({ includeLabels: r9, includeOverlays: false, useCache: false }), o11 = t15.position;
        0 !== i10.w && 0 !== i10.h || ((i10 = { w: e20.pstyle("width").pfValue, h: e20.pstyle("height").pfValue }).x1 = o11.x - i10.w / 2, i10.x2 = o11.x + i10.w / 2, i10.y1 = o11.y - i10.h / 2, i10.y2 = o11.y + i10.h / 2);
        var s10 = a9.width.left.value;
        "px" === a9.width.left.units && a9.width.val > 0 && (s10 = 100 * s10 / a9.width.val);
        var l10 = a9.width.right.value;
        "px" === a9.width.right.units && a9.width.val > 0 && (l10 = 100 * l10 / a9.width.val);
        var u9 = a9.height.top.value;
        "px" === a9.height.top.units && a9.height.val > 0 && (u9 = 100 * u9 / a9.height.val);
        var c9 = a9.height.bottom.value;
        "px" === a9.height.bottom.units && a9.height.val > 0 && (c9 = 100 * c9 / a9.height.val);
        var d10 = y9(a9.width.val - i10.w, s10, l10), h9 = d10.biasDiff, p9 = d10.biasComplementDiff, f10 = y9(a9.height.val - i10.h, u9, c9), g8 = f10.biasDiff, v11 = f10.biasComplementDiff;
        t15.autoPadding = function(e21, t16, n13, r10) {
          if ("%" !== n13.units)
            return "px" === n13.units ? n13.pfValue : 0;
          switch (r10) {
            case "width":
              return e21 > 0 ? n13.pfValue * e21 : 0;
            case "height":
              return t16 > 0 ? n13.pfValue * t16 : 0;
            case "average":
              return e21 > 0 && t16 > 0 ? n13.pfValue * (e21 + t16) / 2 : 0;
            case "min":
              return e21 > 0 && t16 > 0 ? e21 > t16 ? n13.pfValue * t16 : n13.pfValue * e21 : 0;
            case "max":
              return e21 > 0 && t16 > 0 ? e21 > t16 ? n13.pfValue * e21 : n13.pfValue * t16 : 0;
            default:
              return 0;
          }
        }(i10.w, i10.h, e20.pstyle("padding"), e20.pstyle("padding-relative-to").value), t15.autoWidth = Math.max(i10.w, a9.width.val), o11.x = (-h9 + i10.x1 + i10.x2 + p9) / 2, t15.autoHeight = Math.max(i10.h, a9.height.val), o11.y = (-g8 + i10.y1 + i10.y2 + v11) / 2;
      }
      function y9(e21, t16, n13) {
        var r10 = 0, a10 = 0, i11 = t16 + n13;
        return e21 > 0 && i11 > 0 && (r10 = t16 / i11 * e21, a10 = n13 / i11 * e21), { biasDiff: r10, biasComplementDiff: a10 };
      }
    }
    for (var r8 = 0; r8 < this.length; r8++) {
      var a8 = this[r8], i9 = a8._private;
      i9.compoundBoundsClean && !e19 || (n11(a8), t14.batching() || (i9.compoundBoundsClean = true));
    }
    return this;
  };
  var ga = function(e19) {
    return e19 === 1 / 0 || e19 === -1 / 0 ? 0 : e19;
  };
  var va = function(e19, t14, n11, r8, a8) {
    r8 - t14 != 0 && a8 - n11 != 0 && null != t14 && null != n11 && null != r8 && null != a8 && (e19.x1 = t14 < e19.x1 ? t14 : e19.x1, e19.x2 = r8 > e19.x2 ? r8 : e19.x2, e19.y1 = n11 < e19.y1 ? n11 : e19.y1, e19.y2 = a8 > e19.y2 ? a8 : e19.y2, e19.w = e19.x2 - e19.x1, e19.h = e19.y2 - e19.y1);
  };
  var ya = function(e19, t14) {
    return null == t14 ? e19 : va(e19, t14.x1, t14.y1, t14.x2, t14.y2);
  };
  var ma = function(e19, t14, n11) {
    return Oe(e19, t14, n11);
  };
  var ba = function(e19, t14, n11) {
    if (!t14.cy().headless()) {
      var r8, a8, i9 = t14._private, o11 = i9.rstyle, s10 = o11.arrowWidth / 2;
      if ("none" !== t14.pstyle(n11 + "-arrow-shape").value) {
        "source" === n11 ? (r8 = o11.srcX, a8 = o11.srcY) : "target" === n11 ? (r8 = o11.tgtX, a8 = o11.tgtY) : (r8 = o11.midX, a8 = o11.midY);
        var l10 = i9.arrowBounds = i9.arrowBounds || {}, u9 = l10[n11] = l10[n11] || {};
        u9.x1 = r8 - s10, u9.y1 = a8 - s10, u9.x2 = r8 + s10, u9.y2 = a8 + s10, u9.w = u9.x2 - u9.x1, u9.h = u9.y2 - u9.y1, mt4(u9, 1), va(e19, u9.x1, u9.y1, u9.x2, u9.y2);
      }
    }
  };
  var xa = function(e19, t14, n11) {
    if (!t14.cy().headless()) {
      var r8;
      r8 = n11 ? n11 + "-" : "";
      var a8 = t14._private, i9 = a8.rstyle;
      if (t14.pstyle(r8 + "label").strValue) {
        var o11, s10, l10, u9, c9 = t14.pstyle("text-halign"), d10 = t14.pstyle("text-valign"), h9 = ma(i9, "labelWidth", n11), p9 = ma(i9, "labelHeight", n11), f10 = ma(i9, "labelX", n11), g8 = ma(i9, "labelY", n11), v11 = t14.pstyle(r8 + "text-margin-x").pfValue, y9 = t14.pstyle(r8 + "text-margin-y").pfValue, m11 = t14.isEdge(), b10 = t14.pstyle(r8 + "text-rotation"), x10 = t14.pstyle("text-outline-width").pfValue, w9 = t14.pstyle("text-border-width").pfValue / 2, E8 = t14.pstyle("text-background-padding").pfValue, k9 = p9, C8 = h9, S7 = C8 / 2, D7 = k9 / 2;
        if (m11)
          o11 = f10 - S7, s10 = f10 + S7, l10 = g8 - D7, u9 = g8 + D7;
        else {
          switch (c9.value) {
            case "left":
              o11 = f10 - C8, s10 = f10;
              break;
            case "center":
              o11 = f10 - S7, s10 = f10 + S7;
              break;
            case "right":
              o11 = f10, s10 = f10 + C8;
          }
          switch (d10.value) {
            case "top":
              l10 = g8 - k9, u9 = g8;
              break;
            case "center":
              l10 = g8 - D7, u9 = g8 + D7;
              break;
            case "bottom":
              l10 = g8, u9 = g8 + k9;
          }
        }
        o11 += v11 - Math.max(x10, w9) - E8 - 2, s10 += v11 + Math.max(x10, w9) + E8 + 2, l10 += y9 - Math.max(x10, w9) - E8 - 2, u9 += y9 + Math.max(x10, w9) + E8 + 2;
        var P9 = n11 || "main", T8 = a8.labelBounds, M8 = T8[P9] = T8[P9] || {};
        M8.x1 = o11, M8.y1 = l10, M8.x2 = s10, M8.y2 = u9, M8.w = s10 - o11, M8.h = u9 - l10;
        var B8 = m11 && "autorotate" === b10.strValue, _6 = null != b10.pfValue && 0 !== b10.pfValue;
        if (B8 || _6) {
          var N7 = B8 ? ma(a8.rstyle, "labelAngle", n11) : b10.pfValue, I7 = Math.cos(N7), z7 = Math.sin(N7), L9 = (o11 + s10) / 2, A9 = (l10 + u9) / 2;
          if (!m11) {
            switch (c9.value) {
              case "left":
                L9 = s10;
                break;
              case "right":
                L9 = o11;
            }
            switch (d10.value) {
              case "top":
                A9 = u9;
                break;
              case "bottom":
                A9 = l10;
            }
          }
          var O8 = function(e20, t15) {
            return { x: (e20 -= L9) * I7 - (t15 -= A9) * z7 + L9, y: e20 * z7 + t15 * I7 + A9 };
          }, R7 = O8(o11, l10), V6 = O8(o11, u9), F7 = O8(s10, l10), q7 = O8(s10, u9);
          o11 = Math.min(R7.x, V6.x, F7.x, q7.x), s10 = Math.max(R7.x, V6.x, F7.x, q7.x), l10 = Math.min(R7.y, V6.y, F7.y, q7.y), u9 = Math.max(R7.y, V6.y, F7.y, q7.y);
        }
        var j8 = P9 + "Rot", Y5 = T8[j8] = T8[j8] || {};
        Y5.x1 = o11, Y5.y1 = l10, Y5.x2 = s10, Y5.y2 = u9, Y5.w = s10 - o11, Y5.h = u9 - l10, va(e19, o11, l10, s10, u9), va(a8.labelBounds.all, o11, l10, s10, u9);
      }
      return e19;
    }
  };
  var wa = function(e19) {
    var t14 = 0, n11 = function(e20) {
      return (e20 ? 1 : 0) << t14++;
    }, r8 = 0;
    return r8 += n11(e19.incudeNodes), r8 += n11(e19.includeEdges), r8 += n11(e19.includeLabels), r8 += n11(e19.includeMainLabels), r8 += n11(e19.includeSourceLabels), r8 += n11(e19.includeTargetLabels), r8 += n11(e19.includeOverlays);
  };
  var Ea = function(e19) {
    if (e19.isEdge()) {
      var t14 = e19.source().position(), n11 = e19.target().position(), r8 = function(e20) {
        return Math.round(e20);
      };
      return function(e20, t15) {
        var n12 = { value: 0, done: false }, r9 = 0, a8 = e20.length;
        return de({ next: function() {
          return r9 < a8 ? n12.value = e20[r9++] : n12.done = true, n12;
        } }, t15);
      }([r8(t14.x), r8(t14.y), r8(n11.x), r8(n11.y)]);
    }
    return 0;
  };
  var ka = function(e19, t14) {
    var n11, r8 = e19._private, a8 = e19.isEdge(), i9 = (null == t14 ? Sa : wa(t14)) === Sa, o11 = Ea(e19), s10 = r8.bbCachePosKey === o11, l10 = t14.useCache && s10, u9 = function(e20) {
      return null == e20._private.bbCache || e20._private.styleDirty;
    };
    if (!l10 || u9(e19) || a8 && u9(e19.source()) || u9(e19.target()) ? (s10 || e19.recalculateRenderedStyle(l10), n11 = function(e20, t15) {
      var n12, r9, a9, i10, o12, s11, l11, u10 = e20._private.cy, c10 = u10.styleEnabled(), d10 = u10.headless(), h9 = vt4(), p9 = e20._private, f10 = e20.isNode(), g8 = e20.isEdge(), v11 = p9.rstyle, y9 = f10 && c10 ? e20.pstyle("bounds-expansion").pfValue : [0], m11 = function(e21) {
        return "none" !== e21.pstyle("display").value;
      }, b10 = !c10 || m11(e20) && (!g8 || m11(e20.source()) && m11(e20.target()));
      if (b10) {
        var x10 = 0;
        c10 && t15.includeOverlays && 0 !== e20.pstyle("overlay-opacity").value && (x10 = e20.pstyle("overlay-padding").value);
        var w9 = 0;
        c10 && t15.includeUnderlays && 0 !== e20.pstyle("underlay-opacity").value && (w9 = e20.pstyle("underlay-padding").value);
        var E8 = Math.max(x10, w9), k9 = 0;
        if (c10 && (k9 = e20.pstyle("width").pfValue / 2), f10 && t15.includeNodes) {
          var C8 = e20.position();
          o12 = C8.x, s11 = C8.y;
          var S7 = e20.outerWidth() / 2, D7 = e20.outerHeight() / 2;
          va(h9, n12 = o12 - S7, a9 = s11 - D7, r9 = o12 + S7, i10 = s11 + D7);
        } else if (g8 && t15.includeEdges)
          if (c10 && !d10) {
            var P9 = e20.pstyle("curve-style").strValue;
            if (n12 = Math.min(v11.srcX, v11.midX, v11.tgtX), r9 = Math.max(v11.srcX, v11.midX, v11.tgtX), a9 = Math.min(v11.srcY, v11.midY, v11.tgtY), i10 = Math.max(v11.srcY, v11.midY, v11.tgtY), va(h9, n12 -= k9, a9 -= k9, r9 += k9, i10 += k9), "haystack" === P9) {
              var T8 = v11.haystackPts;
              if (T8 && 2 === T8.length) {
                if (n12 = T8[0].x, a9 = T8[0].y, n12 > (r9 = T8[1].x)) {
                  var M8 = n12;
                  n12 = r9, r9 = M8;
                }
                if (a9 > (i10 = T8[1].y)) {
                  var B8 = a9;
                  a9 = i10, i10 = B8;
                }
                va(h9, n12 - k9, a9 - k9, r9 + k9, i10 + k9);
              }
            } else if ("bezier" === P9 || "unbundled-bezier" === P9 || "segments" === P9 || "taxi" === P9) {
              var _6;
              switch (P9) {
                case "bezier":
                case "unbundled-bezier":
                  _6 = v11.bezierPts;
                  break;
                case "segments":
                case "taxi":
                  _6 = v11.linePts;
              }
              if (null != _6)
                for (var N7 = 0; N7 < _6.length; N7++) {
                  var I7 = _6[N7];
                  n12 = I7.x - k9, r9 = I7.x + k9, a9 = I7.y - k9, i10 = I7.y + k9, va(h9, n12, a9, r9, i10);
                }
            }
          } else {
            var z7 = e20.source().position(), L9 = e20.target().position();
            if ((n12 = z7.x) > (r9 = L9.x)) {
              var A9 = n12;
              n12 = r9, r9 = A9;
            }
            if ((a9 = z7.y) > (i10 = L9.y)) {
              var O8 = a9;
              a9 = i10, i10 = O8;
            }
            va(h9, n12 -= k9, a9 -= k9, r9 += k9, i10 += k9);
          }
        if (c10 && t15.includeEdges && g8 && (ba(h9, e20, "mid-source"), ba(h9, e20, "mid-target"), ba(h9, e20, "source"), ba(h9, e20, "target")), c10 && "yes" === e20.pstyle("ghost").value) {
          var R7 = e20.pstyle("ghost-offset-x").pfValue, V6 = e20.pstyle("ghost-offset-y").pfValue;
          va(h9, h9.x1 + R7, h9.y1 + V6, h9.x2 + R7, h9.y2 + V6);
        }
        var F7 = p9.bodyBounds = p9.bodyBounds || {};
        xt4(F7, h9), bt4(F7, y9), mt4(F7, 1), c10 && (n12 = h9.x1, r9 = h9.x2, a9 = h9.y1, i10 = h9.y2, va(h9, n12 - E8, a9 - E8, r9 + E8, i10 + E8));
        var q7 = p9.overlayBounds = p9.overlayBounds || {};
        xt4(q7, h9), bt4(q7, y9), mt4(q7, 1);
        var j8 = p9.labelBounds = p9.labelBounds || {};
        null != j8.all ? ((l11 = j8.all).x1 = 1 / 0, l11.y1 = 1 / 0, l11.x2 = -1 / 0, l11.y2 = -1 / 0, l11.w = 0, l11.h = 0) : j8.all = vt4(), c10 && t15.includeLabels && (t15.includeMainLabels && xa(h9, e20, null), g8 && (t15.includeSourceLabels && xa(h9, e20, "source"), t15.includeTargetLabels && xa(h9, e20, "target")));
      }
      return h9.x1 = ga(h9.x1), h9.y1 = ga(h9.y1), h9.x2 = ga(h9.x2), h9.y2 = ga(h9.y2), h9.w = ga(h9.x2 - h9.x1), h9.h = ga(h9.y2 - h9.y1), h9.w > 0 && h9.h > 0 && b10 && (bt4(h9, y9), mt4(h9, 1)), h9;
    }(e19, Ca), r8.bbCache = n11, r8.bbCachePosKey = o11) : n11 = r8.bbCache, !i9) {
      var c9 = e19.isNode();
      n11 = vt4(), (t14.includeNodes && c9 || t14.includeEdges && !c9) && (t14.includeOverlays ? ya(n11, r8.overlayBounds) : ya(n11, r8.bodyBounds)), t14.includeLabels && (t14.includeMainLabels && (!a8 || t14.includeSourceLabels && t14.includeTargetLabels) ? ya(n11, r8.labelBounds.all) : (t14.includeMainLabels && ya(n11, r8.labelBounds.mainRot), t14.includeSourceLabels && ya(n11, r8.labelBounds.sourceRot), t14.includeTargetLabels && ya(n11, r8.labelBounds.targetRot))), n11.w = n11.x2 - n11.x1, n11.h = n11.y2 - n11.y1;
    }
    return n11;
  };
  var Ca = { includeNodes: true, includeEdges: true, includeLabels: true, includeMainLabels: true, includeSourceLabels: true, includeTargetLabels: true, includeOverlays: true, includeUnderlays: true, useCache: true };
  var Sa = wa(Ca);
  var Da = ze(Ca);
  pa.boundingBox = function(e19) {
    var t14;
    if (1 !== this.length || null == this[0]._private.bbCache || this[0]._private.styleDirty || void 0 !== e19 && void 0 !== e19.useCache && true !== e19.useCache) {
      t14 = vt4();
      var n11 = Da(e19 = e19 || Ca), r8 = this;
      if (r8.cy().styleEnabled())
        for (var a8 = 0; a8 < r8.length; a8++) {
          var i9 = r8[a8], o11 = i9._private, s10 = Ea(i9), l10 = o11.bbCachePosKey === s10, u9 = n11.useCache && l10 && !o11.styleDirty;
          i9.recalculateRenderedStyle(u9);
        }
      this.updateCompoundBounds(!e19.useCache);
      for (var c9 = 0; c9 < r8.length; c9++) {
        var d10 = r8[c9];
        ya(t14, ka(d10, n11));
      }
    } else
      e19 = void 0 === e19 ? Ca : Da(e19), t14 = ka(this[0], e19);
    return t14.x1 = ga(t14.x1), t14.y1 = ga(t14.y1), t14.x2 = ga(t14.x2), t14.y2 = ga(t14.y2), t14.w = ga(t14.x2 - t14.x1), t14.h = ga(t14.y2 - t14.y1), t14;
  }, pa.dirtyBoundingBoxCache = function() {
    for (var e19 = 0; e19 < this.length; e19++) {
      var t14 = this[e19]._private;
      t14.bbCache = null, t14.bbCachePosKey = null, t14.bodyBounds = null, t14.overlayBounds = null, t14.labelBounds.all = null, t14.labelBounds.source = null, t14.labelBounds.target = null, t14.labelBounds.main = null, t14.labelBounds.sourceRot = null, t14.labelBounds.targetRot = null, t14.labelBounds.mainRot = null, t14.arrowBounds.source = null, t14.arrowBounds.target = null, t14.arrowBounds["mid-source"] = null, t14.arrowBounds["mid-target"] = null;
    }
    return this.emitAndNotify("bounds"), this;
  }, pa.boundingBoxAt = function(e19) {
    var t14 = this.nodes(), n11 = this.cy(), r8 = n11.hasCompoundNodes(), a8 = n11.collection();
    if (r8 && (a8 = t14.filter(function(e20) {
      return e20.isParent();
    }), t14 = t14.not(a8)), N6(e19)) {
      var i9 = e19;
      e19 = function() {
        return i9;
      };
    }
    n11.startBatch(), t14.forEach(function(t15, n12) {
      return t15._private.bbAtOldPos = e19(t15, n12);
    }).silentPositions(e19), r8 && (a8.dirtyCompoundBoundsCache(), a8.dirtyBoundingBoxCache(), a8.updateCompoundBounds(true));
    var o11 = function(e20) {
      return { x1: e20.x1, x2: e20.x2, w: e20.w, y1: e20.y1, y2: e20.y2, h: e20.h };
    }(this.boundingBox({ useCache: false }));
    return t14.silentPositions(function(e20) {
      return e20._private.bbAtOldPos;
    }), r8 && (a8.dirtyCompoundBoundsCache(), a8.dirtyBoundingBoxCache(), a8.updateCompoundBounds(true)), n11.endBatch(), o11;
  }, ha.boundingbox = ha.bb = ha.boundingBox, ha.renderedBoundingbox = ha.renderedBoundingBox;
  var Pa;
  var Ta;
  var Ma = pa;
  Pa = Ta = {};
  var Ba = function(e19) {
    e19.uppercaseName = H5(e19.name), e19.autoName = "auto" + e19.uppercaseName, e19.labelName = "label" + e19.uppercaseName, e19.outerName = "outer" + e19.uppercaseName, e19.uppercaseOuterName = H5(e19.outerName), Pa[e19.name] = function() {
      var t14 = this[0], n11 = t14._private, r8 = n11.cy._private.styleEnabled;
      if (t14) {
        if (r8) {
          if (t14.isParent())
            return t14.updateCompoundBounds(), n11[e19.autoName] || 0;
          var a8 = t14.pstyle(e19.name);
          return "label" === a8.strValue ? (t14.recalculateRenderedStyle(), n11.rstyle[e19.labelName] || 0) : a8.pfValue;
        }
        return 1;
      }
    }, Pa["outer" + e19.uppercaseName] = function() {
      var t14 = this[0], n11 = t14._private.cy._private.styleEnabled;
      if (t14)
        return n11 ? t14[e19.name]() + t14.pstyle("border-width").pfValue + 2 * t14.padding() : 1;
    }, Pa["rendered" + e19.uppercaseName] = function() {
      var t14 = this[0];
      if (t14)
        return t14[e19.name]() * this.cy().zoom();
    }, Pa["rendered" + e19.uppercaseOuterName] = function() {
      var t14 = this[0];
      if (t14)
        return t14[e19.outerName]() * this.cy().zoom();
    };
  };
  Ba({ name: "width" }), Ba({ name: "height" }), Ta.padding = function() {
    var e19 = this[0], t14 = e19._private;
    return e19.isParent() ? (e19.updateCompoundBounds(), void 0 !== t14.autoPadding ? t14.autoPadding : e19.pstyle("padding").pfValue) : e19.pstyle("padding").pfValue;
  }, Ta.paddedHeight = function() {
    var e19 = this[0];
    return e19.height() + 2 * e19.padding();
  }, Ta.paddedWidth = function() {
    var e19 = this[0];
    return e19.width() + 2 * e19.padding();
  };
  var _a = Ta;
  var Na = { controlPoints: { get: function(e19) {
    return e19.renderer().getControlPoints(e19);
  }, mult: true }, segmentPoints: { get: function(e19) {
    return e19.renderer().getSegmentPoints(e19);
  }, mult: true }, sourceEndpoint: { get: function(e19) {
    return e19.renderer().getSourceEndpoint(e19);
  } }, targetEndpoint: { get: function(e19) {
    return e19.renderer().getTargetEndpoint(e19);
  } }, midpoint: { get: function(e19) {
    return e19.renderer().getEdgeMidpoint(e19);
  } } };
  var Ia = Object.keys(Na).reduce(function(e19, t14) {
    var n11 = Na[t14], r8 = function(e20) {
      return "rendered" + e20[0].toUpperCase() + e20.substr(1);
    }(t14);
    return e19[t14] = function() {
      return function(e20, t15) {
        if (e20.isEdge())
          return t15(e20);
      }(this, n11.get);
    }, n11.mult ? e19[r8] = function() {
      return function(e20, t15) {
        if (e20.isEdge()) {
          var n12 = e20.cy(), r9 = n12.pan(), a8 = n12.zoom();
          return t15(e20).map(function(e21) {
            return at4(e21, a8, r9);
          });
        }
      }(this, n11.get);
    } : e19[r8] = function() {
      return function(e20, t15) {
        if (e20.isEdge()) {
          var n12 = e20.cy();
          return at4(t15(e20), n12.zoom(), n12.pan());
        }
      }(this, n11.get);
    }, e19;
  }, {});
  var za = J4({}, fa, Ma, _a, Ia);
  var La = function(e19, t14) {
    this.recycle(e19, t14);
  };
  function Aa() {
    return false;
  }
  function Oa() {
    return true;
  }
  La.prototype = { instanceString: function() {
    return "event";
  }, recycle: function(e19, t14) {
    if (this.isImmediatePropagationStopped = this.isPropagationStopped = this.isDefaultPrevented = Aa, null != e19 && e19.preventDefault ? (this.type = e19.type, this.isDefaultPrevented = e19.defaultPrevented ? Oa : Aa) : null != e19 && e19.type ? t14 = e19 : this.type = e19, null != t14 && (this.originalEvent = t14.originalEvent, this.type = null != t14.type ? t14.type : this.type, this.cy = t14.cy, this.target = t14.target, this.position = t14.position, this.renderedPosition = t14.renderedPosition, this.namespace = t14.namespace, this.layout = t14.layout), null != this.cy && null != this.position && null == this.renderedPosition) {
      var n11 = this.position, r8 = this.cy.zoom(), a8 = this.cy.pan();
      this.renderedPosition = { x: n11.x * r8 + a8.x, y: n11.y * r8 + a8.y };
    }
    this.timeStamp = e19 && e19.timeStamp || Date.now();
  }, preventDefault: function() {
    this.isDefaultPrevented = Oa;
    var e19 = this.originalEvent;
    e19 && e19.preventDefault && e19.preventDefault();
  }, stopPropagation: function() {
    this.isPropagationStopped = Oa;
    var e19 = this.originalEvent;
    e19 && e19.stopPropagation && e19.stopPropagation();
  }, stopImmediatePropagation: function() {
    this.isImmediatePropagationStopped = Oa, this.stopPropagation();
  }, isDefaultPrevented: Aa, isPropagationStopped: Aa, isImmediatePropagationStopped: Aa };
  var Ra = /^([^.]+)(\.(?:[^.]+))?$/;
  var Va = { qualifierCompare: function(e19, t14) {
    return e19 === t14;
  }, eventMatches: function() {
    return true;
  }, addEventFields: function() {
  }, callbackContext: function(e19) {
    return e19;
  }, beforeEmit: function() {
  }, afterEmit: function() {
  }, bubble: function() {
    return false;
  }, parent: function() {
    return null;
  }, context: null };
  var Fa = Object.keys(Va);
  var qa = {};
  function ja() {
    for (var e19 = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : qa, t14 = arguments.length > 1 ? arguments[1] : void 0, n11 = 0; n11 < Fa.length; n11++) {
      var r8 = Fa[n11];
      this[r8] = e19[r8] || Va[r8];
    }
    this.context = t14 || this.context, this.listeners = [], this.emitting = 0;
  }
  var Ya = ja.prototype;
  var Xa = function(e19, t14, n11, r8, a8, i9, o11) {
    B5(r8) && (a8 = r8, r8 = null), o11 && (i9 = null == i9 ? o11 : J4({}, i9, o11));
    for (var s10 = _5(n11) ? n11 : n11.split(/\s+/), l10 = 0; l10 < s10.length; l10++) {
      var u9 = s10[l10];
      if (!F5(u9)) {
        var c9 = u9.match(Ra);
        if (c9) {
          if (false === t14(e19, u9, c9[1], c9[2] ? c9[2] : null, r8, a8, i9))
            break;
        }
      }
    }
  };
  var Wa = function(e19, t14) {
    return e19.addEventFields(e19.context, t14), new La(t14.type, t14);
  };
  var Ha = function(e19, t14, n11) {
    if ("event" !== T6(n11))
      if (N6(n11))
        t14(e19, Wa(e19, n11));
      else
        for (var r8 = _5(n11) ? n11 : n11.split(/\s+/), a8 = 0; a8 < r8.length; a8++) {
          var i9 = r8[a8];
          if (!F5(i9)) {
            var o11 = i9.match(Ra);
            if (o11) {
              var s10 = o11[1], l10 = o11[2] ? o11[2] : null;
              t14(e19, Wa(e19, { type: s10, namespace: l10, target: e19.context }));
            }
          }
        }
    else
      t14(e19, n11);
  };
  Ya.on = Ya.addListener = function(e19, t14, n11, r8, a8) {
    return Xa(this, function(e20, t15, n12, r9, a9, i9, o11) {
      B5(i9) && e20.listeners.push({ event: t15, callback: i9, type: n12, namespace: r9, qualifier: a9, conf: o11 });
    }, e19, t14, n11, r8, a8), this;
  }, Ya.one = function(e19, t14, n11, r8) {
    return this.on(e19, t14, n11, r8, { one: true });
  }, Ya.removeListener = Ya.off = function(e19, t14, n11, r8) {
    var a8 = this;
    0 !== this.emitting && (this.listeners = this.listeners.slice());
    for (var i9 = this.listeners, o11 = function(o12) {
      var s11 = i9[o12];
      Xa(a8, function(t15, n12, r9, a9, l10, u9) {
        if ((s11.type === r9 || "*" === e19) && (!a9 && ".*" !== s11.namespace || s11.namespace === a9) && (!l10 || t15.qualifierCompare(s11.qualifier, l10)) && (!u9 || s11.callback === u9))
          return i9.splice(o12, 1), false;
      }, e19, t14, n11, r8);
    }, s10 = i9.length - 1; s10 >= 0; s10--)
      o11(s10);
    return this;
  }, Ya.removeAllListeners = function() {
    return this.removeListener("*");
  }, Ya.emit = Ya.trigger = function(e19, t14, n11) {
    var r8 = this.listeners, a8 = r8.length;
    return this.emitting++, _5(t14) || (t14 = [t14]), Ha(this, function(e20, i9) {
      null != n11 && (r8 = [{ event: i9.event, type: i9.type, namespace: i9.namespace, callback: n11 }], a8 = r8.length);
      for (var o11 = function(n12) {
        var a9 = r8[n12];
        if (a9.type === i9.type && (!a9.namespace || a9.namespace === i9.namespace || ".*" === a9.namespace) && e20.eventMatches(e20.context, a9, i9)) {
          var o12 = [i9];
          null != t14 && function(e21, t15) {
            for (var n13 = 0; n13 < t15.length; n13++) {
              var r9 = t15[n13];
              e21.push(r9);
            }
          }(o12, t14), e20.beforeEmit(e20.context, a9, i9), a9.conf && a9.conf.one && (e20.listeners = e20.listeners.filter(function(e21) {
            return e21 !== a9;
          }));
          var s11 = e20.callbackContext(e20.context, a9, i9), l10 = a9.callback.apply(s11, o12);
          e20.afterEmit(e20.context, a9, i9), false === l10 && (i9.stopPropagation(), i9.preventDefault());
        }
      }, s10 = 0; s10 < a8; s10++)
        o11(s10);
      e20.bubble(e20.context) && !i9.isPropagationStopped() && e20.parent(e20.context).emit(i9, t14);
    }, e19), this.emitting--, this;
  };
  var Ka = { qualifierCompare: function(e19, t14) {
    return null == e19 || null == t14 ? null == e19 && null == t14 : e19.sameText(t14);
  }, eventMatches: function(e19, t14, n11) {
    var r8 = t14.qualifier;
    return null == r8 || e19 !== n11.target && A6(n11.target) && r8.matches(n11.target);
  }, addEventFields: function(e19, t14) {
    t14.cy = e19.cy(), t14.target = e19;
  }, callbackContext: function(e19, t14, n11) {
    return null != t14.qualifier ? n11.target : e19;
  }, beforeEmit: function(e19, t14) {
    t14.conf && t14.conf.once && t14.conf.onceCollection.removeListener(t14.event, t14.qualifier, t14.callback);
  }, bubble: function() {
    return true;
  }, parent: function(e19) {
    return e19.isChild() ? e19.parent() : e19.cy();
  } };
  var Ga = function(e19) {
    return M6(e19) ? new Kr(e19) : e19;
  };
  var Ua = { createEmitter: function() {
    for (var e19 = 0; e19 < this.length; e19++) {
      var t14 = this[e19], n11 = t14._private;
      n11.emitter || (n11.emitter = new ja(Ka, t14));
    }
    return this;
  }, emitter: function() {
    return this._private.emitter;
  }, on: function(e19, t14, n11) {
    for (var r8 = Ga(t14), a8 = 0; a8 < this.length; a8++) {
      this[a8].emitter().on(e19, r8, n11);
    }
    return this;
  }, removeListener: function(e19, t14, n11) {
    for (var r8 = Ga(t14), a8 = 0; a8 < this.length; a8++) {
      this[a8].emitter().removeListener(e19, r8, n11);
    }
    return this;
  }, removeAllListeners: function() {
    for (var e19 = 0; e19 < this.length; e19++) {
      this[e19].emitter().removeAllListeners();
    }
    return this;
  }, one: function(e19, t14, n11) {
    for (var r8 = Ga(t14), a8 = 0; a8 < this.length; a8++) {
      this[a8].emitter().one(e19, r8, n11);
    }
    return this;
  }, once: function(e19, t14, n11) {
    for (var r8 = Ga(t14), a8 = 0; a8 < this.length; a8++) {
      this[a8].emitter().on(e19, r8, n11, { once: true, onceCollection: this });
    }
  }, emit: function(e19, t14) {
    for (var n11 = 0; n11 < this.length; n11++) {
      this[n11].emitter().emit(e19, t14);
    }
    return this;
  }, emitAndNotify: function(e19, t14) {
    if (0 !== this.length)
      return this.cy().notify(e19, this), this.emit(e19, t14), this;
  } };
  ur3.eventAliasesOn(Ua);
  var Za = { nodes: function(e19) {
    return this.filter(function(e20) {
      return e20.isNode();
    }).filter(e19);
  }, edges: function(e19) {
    return this.filter(function(e20) {
      return e20.isEdge();
    }).filter(e19);
  }, byGroup: function() {
    for (var e19 = this.spawn(), t14 = this.spawn(), n11 = 0; n11 < this.length; n11++) {
      var r8 = this[n11];
      r8.isNode() ? e19.push(r8) : t14.push(r8);
    }
    return { nodes: e19, edges: t14 };
  }, filter: function(e19, t14) {
    if (void 0 === e19)
      return this;
    if (M6(e19) || L5(e19))
      return new Kr(e19).filter(this);
    if (B5(e19)) {
      for (var n11 = this.spawn(), r8 = this, a8 = 0; a8 < r8.length; a8++) {
        var i9 = r8[a8];
        (t14 ? e19.apply(t14, [i9, a8, r8]) : e19(i9, a8, r8)) && n11.push(i9);
      }
      return n11;
    }
    return this.spawn();
  }, not: function(e19) {
    if (e19) {
      M6(e19) && (e19 = this.filter(e19));
      for (var t14 = this.spawn(), n11 = 0; n11 < this.length; n11++) {
        var r8 = this[n11];
        e19.has(r8) || t14.push(r8);
      }
      return t14;
    }
    return this;
  }, absoluteComplement: function() {
    return this.cy().mutableElements().not(this);
  }, intersect: function(e19) {
    if (M6(e19)) {
      var t14 = e19;
      return this.filter(t14);
    }
    for (var n11 = this.spawn(), r8 = e19, a8 = this.length < e19.length, i9 = a8 ? this : r8, o11 = a8 ? r8 : this, s10 = 0; s10 < i9.length; s10++) {
      var l10 = i9[s10];
      o11.has(l10) && n11.push(l10);
    }
    return n11;
  }, xor: function(e19) {
    var t14 = this._private.cy;
    M6(e19) && (e19 = t14.$(e19));
    var n11 = this.spawn(), r8 = e19, a8 = function(e20, t15) {
      for (var r9 = 0; r9 < e20.length; r9++) {
        var a9 = e20[r9], i9 = a9._private.data.id;
        t15.hasElementWithId(i9) || n11.push(a9);
      }
    };
    return a8(this, r8), a8(r8, this), n11;
  }, diff: function(e19) {
    var t14 = this._private.cy;
    M6(e19) && (e19 = t14.$(e19));
    var n11 = this.spawn(), r8 = this.spawn(), a8 = this.spawn(), i9 = e19, o11 = function(e20, t15, n12) {
      for (var r9 = 0; r9 < e20.length; r9++) {
        var i10 = e20[r9], o12 = i10._private.data.id;
        t15.hasElementWithId(o12) ? a8.merge(i10) : n12.push(i10);
      }
    };
    return o11(this, i9, n11), o11(i9, this, r8), { left: n11, right: r8, both: a8 };
  }, add: function(e19) {
    var t14 = this._private.cy;
    if (!e19)
      return this;
    if (M6(e19)) {
      var n11 = e19;
      e19 = t14.mutableElements().filter(n11);
    }
    for (var r8 = this.spawnSelf(), a8 = 0; a8 < e19.length; a8++) {
      var i9 = e19[a8], o11 = !this.has(i9);
      o11 && r8.push(i9);
    }
    return r8;
  }, merge: function(e19) {
    var t14 = this._private, n11 = t14.cy;
    if (!e19)
      return this;
    if (e19 && M6(e19)) {
      var r8 = e19;
      e19 = n11.mutableElements().filter(r8);
    }
    for (var a8 = t14.map, i9 = 0; i9 < e19.length; i9++) {
      var o11 = e19[i9], s10 = o11._private.data.id;
      if (!a8.has(s10)) {
        var l10 = this.length++;
        this[l10] = o11, a8.set(s10, { ele: o11, index: l10 });
      }
    }
    return this;
  }, unmergeAt: function(e19) {
    var t14 = this[e19].id(), n11 = this._private.map;
    this[e19] = void 0, n11.delete(t14);
    var r8 = e19 === this.length - 1;
    if (this.length > 1 && !r8) {
      var a8 = this.length - 1, i9 = this[a8], o11 = i9._private.data.id;
      this[a8] = void 0, this[e19] = i9, n11.set(o11, { ele: i9, index: e19 });
    }
    return this.length--, this;
  }, unmergeOne: function(e19) {
    e19 = e19[0];
    var t14 = this._private, n11 = e19._private.data.id, r8 = t14.map.get(n11);
    if (!r8)
      return this;
    var a8 = r8.index;
    return this.unmergeAt(a8), this;
  }, unmerge: function(e19) {
    var t14 = this._private.cy;
    if (!e19)
      return this;
    if (e19 && M6(e19)) {
      var n11 = e19;
      e19 = t14.mutableElements().filter(n11);
    }
    for (var r8 = 0; r8 < e19.length; r8++)
      this.unmergeOne(e19[r8]);
    return this;
  }, unmergeBy: function(e19) {
    for (var t14 = this.length - 1; t14 >= 0; t14--) {
      e19(this[t14]) && this.unmergeAt(t14);
    }
    return this;
  }, map: function(e19, t14) {
    for (var n11 = [], r8 = this, a8 = 0; a8 < r8.length; a8++) {
      var i9 = r8[a8], o11 = t14 ? e19.apply(t14, [i9, a8, r8]) : e19(i9, a8, r8);
      n11.push(o11);
    }
    return n11;
  }, reduce: function(e19, t14) {
    for (var n11 = t14, r8 = this, a8 = 0; a8 < r8.length; a8++)
      n11 = e19(n11, r8[a8], a8, r8);
    return n11;
  }, max: function(e19, t14) {
    for (var n11, r8 = -1 / 0, a8 = this, i9 = 0; i9 < a8.length; i9++) {
      var o11 = a8[i9], s10 = t14 ? e19.apply(t14, [o11, i9, a8]) : e19(o11, i9, a8);
      s10 > r8 && (r8 = s10, n11 = o11);
    }
    return { value: r8, ele: n11 };
  }, min: function(e19, t14) {
    for (var n11, r8 = 1 / 0, a8 = this, i9 = 0; i9 < a8.length; i9++) {
      var o11 = a8[i9], s10 = t14 ? e19.apply(t14, [o11, i9, a8]) : e19(o11, i9, a8);
      s10 < r8 && (r8 = s10, n11 = o11);
    }
    return { value: r8, ele: n11 };
  } };
  var $a = Za;
  $a.u = $a["|"] = $a["+"] = $a.union = $a.or = $a.add, $a["\\"] = $a["!"] = $a["-"] = $a.difference = $a.relativeComplement = $a.subtract = $a.not, $a.n = $a["&"] = $a["."] = $a.and = $a.intersection = $a.intersect, $a["^"] = $a["(+)"] = $a["(-)"] = $a.symmetricDifference = $a.symdiff = $a.xor, $a.fnFilter = $a.filterFn = $a.stdFilter = $a.filter, $a.complement = $a.abscomp = $a.absoluteComplement;
  var Qa = function(e19, t14) {
    var n11 = e19.cy().hasCompoundNodes();
    function r8(e20) {
      var t15 = e20.pstyle("z-compound-depth");
      return "auto" === t15.value ? n11 ? e20.zDepth() : 0 : "bottom" === t15.value ? -1 : "top" === t15.value ? Ee : 0;
    }
    var a8 = r8(e19) - r8(t14);
    if (0 !== a8)
      return a8;
    function i9(e20) {
      return "auto" === e20.pstyle("z-index-compare").value && e20.isNode() ? 1 : 0;
    }
    var o11 = i9(e19) - i9(t14);
    if (0 !== o11)
      return o11;
    var s10 = e19.pstyle("z-index").value - t14.pstyle("z-index").value;
    return 0 !== s10 ? s10 : e19.poolIndex() - t14.poolIndex();
  };
  var Ja = { forEach: function(e19, t14) {
    if (B5(e19))
      for (var n11 = this.length, r8 = 0; r8 < n11; r8++) {
        var a8 = this[r8];
        if (false === (t14 ? e19.apply(t14, [a8, r8, this]) : e19(a8, r8, this)))
          break;
      }
    return this;
  }, toArray: function() {
    for (var e19 = [], t14 = 0; t14 < this.length; t14++)
      e19.push(this[t14]);
    return e19;
  }, slice: function(e19, t14) {
    var n11 = [], r8 = this.length;
    null == t14 && (t14 = r8), null == e19 && (e19 = 0), e19 < 0 && (e19 = r8 + e19), t14 < 0 && (t14 = r8 + t14);
    for (var a8 = e19; a8 >= 0 && a8 < t14 && a8 < r8; a8++)
      n11.push(this[a8]);
    return this.spawn(n11);
  }, size: function() {
    return this.length;
  }, eq: function(e19) {
    return this[e19] || this.spawn();
  }, first: function() {
    return this[0] || this.spawn();
  }, last: function() {
    return this[this.length - 1] || this.spawn();
  }, empty: function() {
    return 0 === this.length;
  }, nonempty: function() {
    return !this.empty();
  }, sort: function(e19) {
    if (!B5(e19))
      return this;
    var t14 = this.toArray().sort(e19);
    return this.spawn(t14);
  }, sortByZIndex: function() {
    return this.sort(Qa);
  }, zDepth: function() {
    var e19 = this[0];
    if (e19) {
      var t14 = e19._private;
      if ("nodes" === t14.group) {
        var n11 = t14.data.parent ? e19.parents().size() : 0;
        return e19.isParent() ? n11 : Ee - 1;
      }
      var r8 = t14.source, a8 = t14.target, i9 = r8.zDepth(), o11 = a8.zDepth();
      return Math.max(i9, o11, 0);
    }
  } };
  Ja.each = Ja.forEach;
  var ei;
  ei = "undefined", ("undefined" == typeof Symbol ? "undefined" : g6(Symbol)) != ei && g6(Symbol.iterator) != ei && (Ja[Symbol.iterator] = function() {
    var e19 = this, t14 = { value: void 0, done: false }, n11 = 0, r8 = this.length;
    return b6({ next: function() {
      return n11 < r8 ? t14.value = e19[n11++] : (t14.value = void 0, t14.done = true), t14;
    } }, Symbol.iterator, function() {
      return this;
    });
  });
  var ti = ze({ nodeDimensionsIncludeLabels: false });
  var ni = { layoutDimensions: function(e19) {
    var t14;
    if (e19 = ti(e19), this.takesUpSpace())
      if (e19.nodeDimensionsIncludeLabels) {
        var n11 = this.boundingBox();
        t14 = { w: n11.w, h: n11.h };
      } else
        t14 = { w: this.outerWidth(), h: this.outerHeight() };
    else
      t14 = { w: 0, h: 0 };
    return 0 !== t14.w && 0 !== t14.h || (t14.w = t14.h = 1), t14;
  }, layoutPositions: function(e19, t14, n11) {
    var r8 = this.nodes().filter(function(e20) {
      return !e20.isParent();
    }), a8 = this.cy(), i9 = t14.eles, o11 = function(e20) {
      return e20.id();
    }, s10 = j6(n11, o11);
    e19.emit({ type: "layoutstart", layout: e19 }), e19.animations = [];
    var l10 = t14.spacingFactor && 1 !== t14.spacingFactor, u9 = function() {
      if (!l10)
        return null;
      for (var e20 = vt4(), t15 = 0; t15 < r8.length; t15++) {
        var n12 = r8[t15], a9 = s10(n12, t15);
        yt4(e20, a9.x, a9.y);
      }
      return e20;
    }(), c9 = j6(function(e20, n12) {
      var r9 = s10(e20, n12);
      l10 && (r9 = function(e21, t15, n13) {
        var r10 = t15.x1 + t15.w / 2, a9 = t15.y1 + t15.h / 2;
        return { x: r10 + (n13.x - r10) * e21, y: a9 + (n13.y - a9) * e21 };
      }(Math.abs(t14.spacingFactor), u9, r9));
      return null != t14.transform && (r9 = t14.transform(e20, r9)), r9;
    }, o11);
    if (t14.animate) {
      for (var d10 = 0; d10 < r8.length; d10++) {
        var h9 = r8[d10], p9 = c9(h9, d10);
        if (null == t14.animateFilter || t14.animateFilter(h9, d10)) {
          var f10 = h9.animation({ position: p9, duration: t14.animationDuration, easing: t14.animationEasing });
          e19.animations.push(f10);
        } else
          h9.position(p9);
      }
      if (t14.fit) {
        var g8 = a8.animation({ fit: { boundingBox: i9.boundingBoxAt(c9), padding: t14.padding }, duration: t14.animationDuration, easing: t14.animationEasing });
        e19.animations.push(g8);
      } else if (void 0 !== t14.zoom && void 0 !== t14.pan) {
        var v11 = a8.animation({ zoom: t14.zoom, pan: t14.pan, duration: t14.animationDuration, easing: t14.animationEasing });
        e19.animations.push(v11);
      }
      e19.animations.forEach(function(e20) {
        return e20.play();
      }), e19.one("layoutready", t14.ready), e19.emit({ type: "layoutready", layout: e19 }), rr4.all(e19.animations.map(function(e20) {
        return e20.promise();
      })).then(function() {
        e19.one("layoutstop", t14.stop), e19.emit({ type: "layoutstop", layout: e19 });
      });
    } else
      r8.positions(c9), t14.fit && a8.fit(t14.eles, t14.padding), null != t14.zoom && a8.zoom(t14.zoom), t14.pan && a8.pan(t14.pan), e19.one("layoutready", t14.ready), e19.emit({ type: "layoutready", layout: e19 }), e19.one("layoutstop", t14.stop), e19.emit({ type: "layoutstop", layout: e19 });
    return this;
  }, layout: function(e19) {
    return this.cy().makeLayout(J4({}, e19, { eles: this }));
  } };
  function ri(e19, t14, n11) {
    var r8, a8 = n11._private, i9 = a8.styleCache = a8.styleCache || [];
    return null != (r8 = i9[e19]) ? r8 : r8 = i9[e19] = t14(n11);
  }
  function ai(e19, t14) {
    return e19 = ve(e19), function(n11) {
      return ri(e19, t14, n11);
    };
  }
  function ii(e19, t14) {
    e19 = ve(e19);
    var n11 = function(e20) {
      return t14.call(e20);
    };
    return function() {
      var t15 = this[0];
      if (t15)
        return ri(e19, n11, t15);
    };
  }
  ni.createLayout = ni.makeLayout = ni.layout;
  var oi = { recalculateRenderedStyle: function(e19) {
    var t14 = this.cy(), n11 = t14.renderer(), r8 = t14.styleEnabled();
    return n11 && r8 && n11.recalculateRenderedStyle(this, e19), this;
  }, dirtyStyleCache: function() {
    var e19, t14 = this.cy(), n11 = function(e20) {
      return e20._private.styleCache = null;
    };
    t14.hasCompoundNodes() ? ((e19 = this.spawnSelf().merge(this.descendants()).merge(this.parents())).merge(e19.connectedEdges()), e19.forEach(n11)) : this.forEach(function(e20) {
      n11(e20), e20.connectedEdges().forEach(n11);
    });
    return this;
  }, updateStyle: function(e19) {
    var t14 = this._private.cy;
    if (!t14.styleEnabled())
      return this;
    if (t14.batching())
      return t14._private.batchStyleEles.merge(this), this;
    var n11 = this;
    e19 = !(!e19 && void 0 !== e19), t14.hasCompoundNodes() && (n11 = this.spawnSelf().merge(this.descendants()).merge(this.parents()));
    var r8 = n11;
    return e19 ? r8.emitAndNotify("style") : r8.emit("style"), n11.forEach(function(e20) {
      return e20._private.styleDirty = true;
    }), this;
  }, cleanStyle: function() {
    var e19 = this.cy();
    if (e19.styleEnabled())
      for (var t14 = 0; t14 < this.length; t14++) {
        var n11 = this[t14];
        n11._private.styleDirty && (n11._private.styleDirty = false, e19.style().apply(n11));
      }
  }, parsedStyle: function(e19) {
    var t14 = !(arguments.length > 1 && void 0 !== arguments[1]) || arguments[1], n11 = this[0], r8 = n11.cy();
    if (r8.styleEnabled() && n11) {
      this.cleanStyle();
      var a8 = n11._private.style[e19];
      return null != a8 ? a8 : t14 ? r8.style().getDefaultProperty(e19) : null;
    }
  }, numericStyle: function(e19) {
    var t14 = this[0];
    if (t14.cy().styleEnabled() && t14) {
      var n11 = t14.pstyle(e19);
      return void 0 !== n11.pfValue ? n11.pfValue : n11.value;
    }
  }, numericStyleUnits: function(e19) {
    var t14 = this[0];
    if (t14.cy().styleEnabled())
      return t14 ? t14.pstyle(e19).units : void 0;
  }, renderedStyle: function(e19) {
    var t14 = this.cy();
    if (!t14.styleEnabled())
      return this;
    var n11 = this[0];
    return n11 ? t14.style().getRenderedStyle(n11, e19) : void 0;
  }, style: function(e19, t14) {
    var n11 = this.cy();
    if (!n11.styleEnabled())
      return this;
    var r8 = n11.style();
    if (N6(e19)) {
      var a8 = e19;
      r8.applyBypass(this, a8, false), this.emitAndNotify("style");
    } else if (M6(e19)) {
      if (void 0 === t14) {
        var i9 = this[0];
        return i9 ? r8.getStylePropertyValue(i9, e19) : void 0;
      }
      r8.applyBypass(this, e19, t14, false), this.emitAndNotify("style");
    } else if (void 0 === e19) {
      var o11 = this[0];
      return o11 ? r8.getRawStyle(o11) : void 0;
    }
    return this;
  }, removeStyle: function(e19) {
    var t14 = this.cy();
    if (!t14.styleEnabled())
      return this;
    var n11 = t14.style(), r8 = this;
    if (void 0 === e19)
      for (var a8 = 0; a8 < r8.length; a8++) {
        var i9 = r8[a8];
        n11.removeAllBypasses(i9, false);
      }
    else {
      e19 = e19.split(/\s+/);
      for (var o11 = 0; o11 < r8.length; o11++) {
        var s10 = r8[o11];
        n11.removeBypasses(s10, e19, false);
      }
    }
    return this.emitAndNotify("style"), this;
  }, show: function() {
    return this.css("display", "element"), this;
  }, hide: function() {
    return this.css("display", "none"), this;
  }, effectiveOpacity: function() {
    var e19 = this.cy();
    if (!e19.styleEnabled())
      return 1;
    var t14 = e19.hasCompoundNodes(), n11 = this[0];
    if (n11) {
      var r8 = n11._private, a8 = n11.pstyle("opacity").value;
      if (!t14)
        return a8;
      var i9 = r8.data.parent ? n11.parents() : null;
      if (i9)
        for (var o11 = 0; o11 < i9.length; o11++) {
          a8 *= i9[o11].pstyle("opacity").value;
        }
      return a8;
    }
  }, transparent: function() {
    if (!this.cy().styleEnabled())
      return false;
    var e19 = this[0], t14 = e19.cy().hasCompoundNodes();
    return e19 ? t14 ? 0 === e19.effectiveOpacity() : 0 === e19.pstyle("opacity").value : void 0;
  }, backgrounding: function() {
    return !!this.cy().styleEnabled() && !!this[0]._private.backgrounding;
  } };
  function si(e19, t14) {
    var n11 = e19._private.data.parent ? e19.parents() : null;
    if (n11)
      for (var r8 = 0; r8 < n11.length; r8++) {
        if (!t14(n11[r8]))
          return false;
      }
    return true;
  }
  function li(e19) {
    var t14 = e19.ok, n11 = e19.edgeOkViaNode || e19.ok, r8 = e19.parentOk || e19.ok;
    return function() {
      var e20 = this.cy();
      if (!e20.styleEnabled())
        return true;
      var a8 = this[0], i9 = e20.hasCompoundNodes();
      if (a8) {
        var o11 = a8._private;
        if (!t14(a8))
          return false;
        if (a8.isNode())
          return !i9 || si(a8, r8);
        var s10 = o11.source, l10 = o11.target;
        return n11(s10) && (!i9 || si(s10, n11)) && (s10 === l10 || n11(l10) && (!i9 || si(l10, n11)));
      }
    };
  }
  var ui = ai("eleTakesUpSpace", function(e19) {
    return "element" === e19.pstyle("display").value && 0 !== e19.width() && (!e19.isNode() || 0 !== e19.height());
  });
  oi.takesUpSpace = ii("takesUpSpace", li({ ok: ui }));
  var ci = ai("eleInteractive", function(e19) {
    return "yes" === e19.pstyle("events").value && "visible" === e19.pstyle("visibility").value && ui(e19);
  });
  var di = ai("parentInteractive", function(e19) {
    return "visible" === e19.pstyle("visibility").value && ui(e19);
  });
  oi.interactive = ii("interactive", li({ ok: ci, parentOk: di, edgeOkViaNode: ui })), oi.noninteractive = function() {
    var e19 = this[0];
    if (e19)
      return !e19.interactive();
  };
  var hi = ai("eleVisible", function(e19) {
    return "visible" === e19.pstyle("visibility").value && 0 !== e19.pstyle("opacity").pfValue && ui(e19);
  });
  var pi = ui;
  oi.visible = ii("visible", li({ ok: hi, edgeOkViaNode: pi })), oi.hidden = function() {
    var e19 = this[0];
    if (e19)
      return !e19.visible();
  }, oi.isBundledBezier = ii("isBundledBezier", function() {
    return !!this.cy().styleEnabled() && (!this.removed() && "bezier" === this.pstyle("curve-style").value && this.takesUpSpace());
  }), oi.bypass = oi.css = oi.style, oi.renderedCss = oi.renderedStyle, oi.removeBypass = oi.removeCss = oi.removeStyle, oi.pstyle = oi.parsedStyle;
  var fi = {};
  function gi(e19) {
    return function() {
      var t14 = arguments, n11 = [];
      if (2 === t14.length) {
        var r8 = t14[0], a8 = t14[1];
        this.on(e19.event, r8, a8);
      } else if (1 === t14.length && B5(t14[0])) {
        var i9 = t14[0];
        this.on(e19.event, i9);
      } else if (0 === t14.length || 1 === t14.length && _5(t14[0])) {
        for (var o11 = 1 === t14.length ? t14[0] : null, s10 = 0; s10 < this.length; s10++) {
          var l10 = this[s10], u9 = !e19.ableField || l10._private[e19.ableField], c9 = l10._private[e19.field] != e19.value;
          if (e19.overrideAble) {
            var d10 = e19.overrideAble(l10);
            if (void 0 !== d10 && (u9 = d10, !d10))
              return this;
          }
          u9 && (l10._private[e19.field] = e19.value, c9 && n11.push(l10));
        }
        var h9 = this.spawn(n11);
        h9.updateStyle(), h9.emit(e19.event), o11 && h9.emit(o11);
      }
      return this;
    };
  }
  function vi(e19) {
    fi[e19.field] = function() {
      var t14 = this[0];
      if (t14) {
        if (e19.overrideField) {
          var n11 = e19.overrideField(t14);
          if (void 0 !== n11)
            return n11;
        }
        return t14._private[e19.field];
      }
    }, fi[e19.on] = gi({ event: e19.on, field: e19.field, ableField: e19.ableField, overrideAble: e19.overrideAble, value: true }), fi[e19.off] = gi({ event: e19.off, field: e19.field, ableField: e19.ableField, overrideAble: e19.overrideAble, value: false });
  }
  vi({ field: "locked", overrideField: function(e19) {
    return !!e19.cy().autolock() || void 0;
  }, on: "lock", off: "unlock" }), vi({ field: "grabbable", overrideField: function(e19) {
    return !e19.cy().autoungrabify() && !e19.pannable() && void 0;
  }, on: "grabify", off: "ungrabify" }), vi({ field: "selected", ableField: "selectable", overrideAble: function(e19) {
    return !e19.cy().autounselectify() && void 0;
  }, on: "select", off: "unselect" }), vi({ field: "selectable", overrideField: function(e19) {
    return !e19.cy().autounselectify() && void 0;
  }, on: "selectify", off: "unselectify" }), fi.deselect = fi.unselect, fi.grabbed = function() {
    var e19 = this[0];
    if (e19)
      return e19._private.grabbed;
  }, vi({ field: "active", on: "activate", off: "unactivate" }), vi({ field: "pannable", on: "panify", off: "unpanify" }), fi.inactive = function() {
    var e19 = this[0];
    if (e19)
      return !e19._private.active;
  };
  var yi = {};
  var mi = function(e19) {
    return function(t14) {
      for (var n11 = [], r8 = 0; r8 < this.length; r8++) {
        var a8 = this[r8];
        if (a8.isNode()) {
          for (var i9 = false, o11 = a8.connectedEdges(), s10 = 0; s10 < o11.length; s10++) {
            var l10 = o11[s10], u9 = l10.source(), c9 = l10.target();
            if (e19.noIncomingEdges && c9 === a8 && u9 !== a8 || e19.noOutgoingEdges && u9 === a8 && c9 !== a8) {
              i9 = true;
              break;
            }
          }
          i9 || n11.push(a8);
        }
      }
      return this.spawn(n11, true).filter(t14);
    };
  };
  var bi = function(e19) {
    return function(t14) {
      for (var n11 = [], r8 = 0; r8 < this.length; r8++) {
        var a8 = this[r8];
        if (a8.isNode())
          for (var i9 = a8.connectedEdges(), o11 = 0; o11 < i9.length; o11++) {
            var s10 = i9[o11], l10 = s10.source(), u9 = s10.target();
            e19.outgoing && l10 === a8 ? (n11.push(s10), n11.push(u9)) : e19.incoming && u9 === a8 && (n11.push(s10), n11.push(l10));
          }
      }
      return this.spawn(n11, true).filter(t14);
    };
  };
  var xi = function(e19) {
    return function(t14) {
      for (var n11 = this, r8 = [], a8 = {}; ; ) {
        var i9 = e19.outgoing ? n11.outgoers() : n11.incomers();
        if (0 === i9.length)
          break;
        for (var o11 = false, s10 = 0; s10 < i9.length; s10++) {
          var l10 = i9[s10], u9 = l10.id();
          a8[u9] || (a8[u9] = true, r8.push(l10), o11 = true);
        }
        if (!o11)
          break;
        n11 = i9;
      }
      return this.spawn(r8, true).filter(t14);
    };
  };
  function wi(e19) {
    return function(t14) {
      for (var n11 = [], r8 = 0; r8 < this.length; r8++) {
        var a8 = this[r8]._private[e19.attr];
        a8 && n11.push(a8);
      }
      return this.spawn(n11, true).filter(t14);
    };
  }
  function Ei(e19) {
    return function(t14) {
      var n11 = [], r8 = this._private.cy, a8 = e19 || {};
      M6(t14) && (t14 = r8.$(t14));
      for (var i9 = 0; i9 < t14.length; i9++)
        for (var o11 = t14[i9]._private.edges, s10 = 0; s10 < o11.length; s10++) {
          var l10 = o11[s10], u9 = l10._private.data, c9 = this.hasElementWithId(u9.source) && t14.hasElementWithId(u9.target), d10 = t14.hasElementWithId(u9.source) && this.hasElementWithId(u9.target);
          if (c9 || d10) {
            if (a8.thisIsSrc || a8.thisIsTgt) {
              if (a8.thisIsSrc && !c9)
                continue;
              if (a8.thisIsTgt && !d10)
                continue;
            }
            n11.push(l10);
          }
        }
      return this.spawn(n11, true);
    };
  }
  function ki(e19) {
    return e19 = J4({}, { codirected: false }, e19), function(t14) {
      for (var n11 = [], r8 = this.edges(), a8 = e19, i9 = 0; i9 < r8.length; i9++)
        for (var o11 = r8[i9]._private, s10 = o11.source, l10 = s10._private.data.id, u9 = o11.data.target, c9 = s10._private.edges, d10 = 0; d10 < c9.length; d10++) {
          var h9 = c9[d10], p9 = h9._private.data, f10 = p9.target, g8 = p9.source, v11 = f10 === u9 && g8 === l10, y9 = l10 === f10 && u9 === g8;
          (a8.codirected && v11 || !a8.codirected && (v11 || y9)) && n11.push(h9);
        }
      return this.spawn(n11, true).filter(t14);
    };
  }
  yi.clearTraversalCache = function() {
    for (var e19 = 0; e19 < this.length; e19++)
      this[e19]._private.traversalCache = null;
  }, J4(yi, { roots: mi({ noIncomingEdges: true }), leaves: mi({ noOutgoingEdges: true }), outgoers: Qr(bi({ outgoing: true }), "outgoers"), successors: xi({ outgoing: true }), incomers: Qr(bi({ incoming: true }), "incomers"), predecessors: xi({ incoming: true }) }), J4(yi, { neighborhood: Qr(function(e19) {
    for (var t14 = [], n11 = this.nodes(), r8 = 0; r8 < n11.length; r8++)
      for (var a8 = n11[r8], i9 = a8.connectedEdges(), o11 = 0; o11 < i9.length; o11++) {
        var s10 = i9[o11], l10 = s10.source(), u9 = s10.target(), c9 = a8 === l10 ? u9 : l10;
        c9.length > 0 && t14.push(c9[0]), t14.push(s10[0]);
      }
    return this.spawn(t14, true).filter(e19);
  }, "neighborhood"), closedNeighborhood: function(e19) {
    return this.neighborhood().add(this).filter(e19);
  }, openNeighborhood: function(e19) {
    return this.neighborhood(e19);
  } }), yi.neighbourhood = yi.neighborhood, yi.closedNeighbourhood = yi.closedNeighborhood, yi.openNeighbourhood = yi.openNeighborhood, J4(yi, { source: Qr(function(e19) {
    var t14, n11 = this[0];
    return n11 && (t14 = n11._private.source || n11.cy().collection()), t14 && e19 ? t14.filter(e19) : t14;
  }, "source"), target: Qr(function(e19) {
    var t14, n11 = this[0];
    return n11 && (t14 = n11._private.target || n11.cy().collection()), t14 && e19 ? t14.filter(e19) : t14;
  }, "target"), sources: wi({ attr: "source" }), targets: wi({ attr: "target" }) }), J4(yi, { edgesWith: Qr(Ei(), "edgesWith"), edgesTo: Qr(Ei({ thisIsSrc: true }), "edgesTo") }), J4(yi, { connectedEdges: Qr(function(e19) {
    for (var t14 = [], n11 = 0; n11 < this.length; n11++) {
      var r8 = this[n11];
      if (r8.isNode())
        for (var a8 = r8._private.edges, i9 = 0; i9 < a8.length; i9++) {
          var o11 = a8[i9];
          t14.push(o11);
        }
    }
    return this.spawn(t14, true).filter(e19);
  }, "connectedEdges"), connectedNodes: Qr(function(e19) {
    for (var t14 = [], n11 = 0; n11 < this.length; n11++) {
      var r8 = this[n11];
      r8.isEdge() && (t14.push(r8.source()[0]), t14.push(r8.target()[0]));
    }
    return this.spawn(t14, true).filter(e19);
  }, "connectedNodes"), parallelEdges: Qr(ki(), "parallelEdges"), codirectedEdges: Qr(ki({ codirected: true }), "codirectedEdges") }), J4(yi, { components: function(e19) {
    var t14 = this, n11 = t14.cy(), r8 = n11.collection(), a8 = null == e19 ? t14.nodes() : e19.nodes(), i9 = [];
    null != e19 && a8.empty() && (a8 = e19.sources());
    var o11 = function(e20, t15) {
      r8.merge(e20), a8.unmerge(e20), t15.merge(e20);
    };
    if (a8.empty())
      return t14.spawn();
    var s10 = function() {
      var e20 = n11.collection();
      i9.push(e20);
      var r9 = a8[0];
      o11(r9, e20), t14.bfs({ directed: false, roots: r9, visit: function(t15) {
        return o11(t15, e20);
      } }), e20.forEach(function(n12) {
        n12.connectedEdges().forEach(function(n13) {
          t14.has(n13) && e20.has(n13.source()) && e20.has(n13.target()) && e20.merge(n13);
        });
      });
    };
    do {
      s10();
    } while (a8.length > 0);
    return i9;
  }, component: function() {
    var e19 = this[0];
    return e19.cy().mutableElements().components(e19)[0];
  } }), yi.componentsOf = yi.components;
  var Ci = function(e19, t14) {
    var n11 = arguments.length > 2 && void 0 !== arguments[2] && arguments[2], r8 = arguments.length > 3 && void 0 !== arguments[3] && arguments[3];
    if (void 0 !== e19) {
      var a8 = new Ve(), i9 = false;
      if (t14) {
        if (t14.length > 0 && N6(t14[0]) && !A6(t14[0])) {
          i9 = true;
          for (var o11 = [], s10 = new qe(), l10 = 0, u9 = t14.length; l10 < u9; l10++) {
            var c9 = t14[l10];
            null == c9.data && (c9.data = {});
            var d10 = c9.data;
            if (null == d10.id)
              d10.id = _e();
            else if (e19.hasElementWithId(d10.id) || s10.has(d10.id))
              continue;
            var h9 = new je(e19, c9, false);
            o11.push(h9), s10.add(d10.id);
          }
          t14 = o11;
        }
      } else
        t14 = [];
      this.length = 0;
      for (var p9 = 0, f10 = t14.length; p9 < f10; p9++) {
        var g8 = t14[p9][0];
        if (null != g8) {
          var v11 = g8._private.data.id;
          n11 && a8.has(v11) || (n11 && a8.set(v11, { index: this.length, ele: g8 }), this[this.length] = g8, this.length++);
        }
      }
      this._private = { eles: this, cy: e19, get map() {
        return null == this.lazyMap && this.rebuildMap(), this.lazyMap;
      }, set map(e20) {
        this.lazyMap = e20;
      }, rebuildMap: function() {
        for (var e20 = this.lazyMap = new Ve(), t15 = this.eles, n12 = 0; n12 < t15.length; n12++) {
          var r9 = t15[n12];
          e20.set(r9.id(), { index: n12, ele: r9 });
        }
      } }, n11 && (this._private.map = a8), i9 && !r8 && this.restore();
    } else
      Pe("A collection must have a reference to the core");
  };
  var Si = je.prototype = Ci.prototype = Object.create(Array.prototype);
  Si.instanceString = function() {
    return "collection";
  }, Si.spawn = function(e19, t14) {
    return new Ci(this.cy(), e19, t14);
  }, Si.spawnSelf = function() {
    return this.spawn(this);
  }, Si.cy = function() {
    return this._private.cy;
  }, Si.renderer = function() {
    return this._private.cy.renderer();
  }, Si.element = function() {
    return this[0];
  }, Si.collection = function() {
    return O6(this) ? this : new Ci(this._private.cy, [this]);
  }, Si.unique = function() {
    return new Ci(this._private.cy, this, true);
  }, Si.hasElementWithId = function(e19) {
    return e19 = "" + e19, this._private.map.has(e19);
  }, Si.getElementById = function(e19) {
    e19 = "" + e19;
    var t14 = this._private.cy, n11 = this._private.map.get(e19);
    return n11 ? n11.ele : new Ci(t14);
  }, Si.$id = Si.getElementById, Si.poolIndex = function() {
    var e19 = this._private.cy._private.elements, t14 = this[0]._private.data.id;
    return e19._private.map.get(t14).index;
  }, Si.indexOf = function(e19) {
    var t14 = e19[0]._private.data.id;
    return this._private.map.get(t14).index;
  }, Si.indexOfId = function(e19) {
    return e19 = "" + e19, this._private.map.get(e19).index;
  }, Si.json = function(e19) {
    var t14 = this.element(), n11 = this.cy();
    if (null == t14 && e19)
      return this;
    if (null != t14) {
      var r8 = t14._private;
      if (N6(e19)) {
        if (n11.startBatch(), e19.data) {
          t14.data(e19.data);
          var a8 = r8.data;
          if (t14.isEdge()) {
            var i9 = false, o11 = {}, s10 = e19.data.source, l10 = e19.data.target;
            null != s10 && s10 != a8.source && (o11.source = "" + s10, i9 = true), null != l10 && l10 != a8.target && (o11.target = "" + l10, i9 = true), i9 && (t14 = t14.move(o11));
          } else {
            var u9 = "parent" in e19.data, c9 = e19.data.parent;
            !u9 || null == c9 && null == a8.parent || c9 == a8.parent || (void 0 === c9 && (c9 = null), null != c9 && (c9 = "" + c9), t14 = t14.move({ parent: c9 }));
          }
        }
        e19.position && t14.position(e19.position);
        var d10 = function(n12, a9, i10) {
          var o12 = e19[n12];
          null != o12 && o12 !== r8[n12] && (o12 ? t14[a9]() : t14[i10]());
        };
        return d10("removed", "remove", "restore"), d10("selected", "select", "unselect"), d10("selectable", "selectify", "unselectify"), d10("locked", "lock", "unlock"), d10("grabbable", "grabify", "ungrabify"), d10("pannable", "panify", "unpanify"), null != e19.classes && t14.classes(e19.classes), n11.endBatch(), this;
      }
      if (void 0 === e19) {
        var h9 = { data: Be(r8.data), position: Be(r8.position), group: r8.group, removed: r8.removed, selected: r8.selected, selectable: r8.selectable, locked: r8.locked, grabbable: r8.grabbable, pannable: r8.pannable, classes: null };
        h9.classes = "";
        var p9 = 0;
        return r8.classes.forEach(function(e20) {
          return h9.classes += 0 == p9++ ? e20 : " " + e20;
        }), h9;
      }
    }
  }, Si.jsons = function() {
    for (var e19 = [], t14 = 0; t14 < this.length; t14++) {
      var n11 = this[t14].json();
      e19.push(n11);
    }
    return e19;
  }, Si.clone = function() {
    for (var e19 = this.cy(), t14 = [], n11 = 0; n11 < this.length; n11++) {
      var r8 = this[n11].json(), a8 = new je(e19, r8, false);
      t14.push(a8);
    }
    return new Ci(e19, t14);
  }, Si.copy = Si.clone, Si.restore = function() {
    for (var e19, t14, n11 = !(arguments.length > 0 && void 0 !== arguments[0]) || arguments[0], r8 = !(arguments.length > 1 && void 0 !== arguments[1]) || arguments[1], a8 = this, i9 = a8.cy(), o11 = i9._private, s10 = [], l10 = [], u9 = 0, c9 = a8.length; u9 < c9; u9++) {
      var d10 = a8[u9];
      r8 && !d10.removed() || (d10.isNode() ? s10.push(d10) : l10.push(d10));
    }
    e19 = s10.concat(l10);
    var h9 = function() {
      e19.splice(t14, 1), t14--;
    };
    for (t14 = 0; t14 < e19.length; t14++) {
      var p9 = e19[t14], f10 = p9._private, g8 = f10.data;
      if (p9.clearTraversalCache(), r8 || f10.removed)
        if (void 0 === g8.id)
          g8.id = _e();
        else if (I6(g8.id))
          g8.id = "" + g8.id;
        else {
          if (F5(g8.id) || !M6(g8.id)) {
            Pe("Can not create element with invalid string ID `" + g8.id + "`"), h9();
            continue;
          }
          if (i9.hasElementWithId(g8.id)) {
            Pe("Can not create second element with ID `" + g8.id + "`"), h9();
            continue;
          }
        }
      else
        ;
      var v11 = g8.id;
      if (p9.isNode()) {
        var y9 = f10.position;
        null == y9.x && (y9.x = 0), null == y9.y && (y9.y = 0);
      }
      if (p9.isEdge()) {
        for (var m11 = p9, b10 = ["source", "target"], x10 = b10.length, w9 = false, E8 = 0; E8 < x10; E8++) {
          var k9 = b10[E8], C8 = g8[k9];
          I6(C8) && (C8 = g8[k9] = "" + g8[k9]), null == C8 || "" === C8 ? (Pe("Can not create edge `" + v11 + "` with unspecified " + k9), w9 = true) : i9.hasElementWithId(C8) || (Pe("Can not create edge `" + v11 + "` with nonexistant " + k9 + " `" + C8 + "`"), w9 = true);
        }
        if (w9) {
          h9();
          continue;
        }
        var S7 = i9.getElementById(g8.source), D7 = i9.getElementById(g8.target);
        S7.same(D7) ? S7._private.edges.push(m11) : (S7._private.edges.push(m11), D7._private.edges.push(m11)), m11._private.source = S7, m11._private.target = D7;
      }
      f10.map = new Ve(), f10.map.set(v11, { ele: p9, index: 0 }), f10.removed = false, r8 && i9.addToPool(p9);
    }
    for (var P9 = 0; P9 < s10.length; P9++) {
      var T8 = s10[P9], B8 = T8._private.data;
      I6(B8.parent) && (B8.parent = "" + B8.parent);
      var _6 = B8.parent;
      if (null != _6 || T8._private.parent) {
        var N7 = T8._private.parent ? i9.collection().merge(T8._private.parent) : i9.getElementById(_6);
        if (N7.empty())
          B8.parent = void 0;
        else if (N7[0].removed())
          Me("Node added with missing parent, reference to parent removed"), B8.parent = void 0, T8._private.parent = null;
        else {
          for (var z7 = false, L9 = N7; !L9.empty(); ) {
            if (T8.same(L9)) {
              z7 = true, B8.parent = void 0;
              break;
            }
            L9 = L9.parent();
          }
          z7 || (N7[0]._private.children.push(T8), T8._private.parent = N7[0], o11.hasCompoundNodes = true);
        }
      }
    }
    if (e19.length > 0) {
      for (var A9 = e19.length === a8.length ? a8 : new Ci(i9, e19), O8 = 0; O8 < A9.length; O8++) {
        var R7 = A9[O8];
        R7.isNode() || (R7.parallelEdges().clearTraversalCache(), R7.source().clearTraversalCache(), R7.target().clearTraversalCache());
      }
      (o11.hasCompoundNodes ? i9.collection().merge(A9).merge(A9.connectedNodes()).merge(A9.parent()) : A9).dirtyCompoundBoundsCache().dirtyBoundingBoxCache().updateStyle(n11), n11 ? A9.emitAndNotify("add") : r8 && A9.emit("add");
    }
    return a8;
  }, Si.removed = function() {
    var e19 = this[0];
    return e19 && e19._private.removed;
  }, Si.inside = function() {
    var e19 = this[0];
    return e19 && !e19._private.removed;
  }, Si.remove = function() {
    var e19 = !(arguments.length > 0 && void 0 !== arguments[0]) || arguments[0], t14 = !(arguments.length > 1 && void 0 !== arguments[1]) || arguments[1], n11 = this, r8 = [], a8 = {}, i9 = n11._private.cy;
    function o11(e20) {
      var n12 = a8[e20.id()];
      t14 && e20.removed() || n12 || (a8[e20.id()] = true, e20.isNode() ? (r8.push(e20), function(e21) {
        for (var t15 = e21._private.edges, n13 = 0; n13 < t15.length; n13++)
          o11(t15[n13]);
      }(e20), function(e21) {
        for (var t15 = e21._private.children, n13 = 0; n13 < t15.length; n13++)
          o11(t15[n13]);
      }(e20)) : r8.unshift(e20));
    }
    for (var s10 = 0, l10 = n11.length; s10 < l10; s10++) {
      o11(n11[s10]);
    }
    function u9(e20, t15) {
      var n12 = e20._private.edges;
      Le(n12, t15), e20.clearTraversalCache();
    }
    function c9(e20) {
      e20.clearTraversalCache();
    }
    var d10 = [];
    function h9(e20, t15) {
      t15 = t15[0];
      var n12 = (e20 = e20[0])._private.children, r9 = e20.id();
      Le(n12, t15), t15._private.parent = null, d10.ids[r9] || (d10.ids[r9] = true, d10.push(e20));
    }
    d10.ids = {}, n11.dirtyCompoundBoundsCache(), t14 && i9.removeFromPool(r8);
    for (var p9 = 0; p9 < r8.length; p9++) {
      var f10 = r8[p9];
      if (f10.isEdge()) {
        var g8 = f10.source()[0], v11 = f10.target()[0];
        u9(g8, f10), u9(v11, f10);
        for (var y9 = f10.parallelEdges(), m11 = 0; m11 < y9.length; m11++) {
          var b10 = y9[m11];
          c9(b10), b10.isBundledBezier() && b10.dirtyBoundingBoxCache();
        }
      } else {
        var x10 = f10.parent();
        0 !== x10.length && h9(x10, f10);
      }
      t14 && (f10._private.removed = true);
    }
    var w9 = i9._private.elements;
    i9._private.hasCompoundNodes = false;
    for (var E8 = 0; E8 < w9.length; E8++) {
      if (w9[E8].isParent()) {
        i9._private.hasCompoundNodes = true;
        break;
      }
    }
    var k9 = new Ci(this.cy(), r8);
    k9.size() > 0 && (e19 ? k9.emitAndNotify("remove") : t14 && k9.emit("remove"));
    for (var C8 = 0; C8 < d10.length; C8++) {
      var S7 = d10[C8];
      t14 && S7.removed() || S7.updateStyle();
    }
    return k9;
  }, Si.move = function(e19) {
    var t14 = this._private.cy, n11 = this, r8 = false, a8 = false, i9 = function(e20) {
      return null == e20 ? e20 : "" + e20;
    };
    if (void 0 !== e19.source || void 0 !== e19.target) {
      var o11 = i9(e19.source), s10 = i9(e19.target), l10 = null != o11 && t14.hasElementWithId(o11), u9 = null != s10 && t14.hasElementWithId(s10);
      (l10 || u9) && (t14.batch(function() {
        n11.remove(r8, a8), n11.emitAndNotify("moveout");
        for (var e20 = 0; e20 < n11.length; e20++) {
          var t15 = n11[e20], i10 = t15._private.data;
          t15.isEdge() && (l10 && (i10.source = o11), u9 && (i10.target = s10));
        }
        n11.restore(r8, a8);
      }), n11.emitAndNotify("move"));
    } else if (void 0 !== e19.parent) {
      var c9 = i9(e19.parent);
      if (null === c9 || t14.hasElementWithId(c9)) {
        var d10 = null === c9 ? void 0 : c9;
        t14.batch(function() {
          var e20 = n11.remove(r8, a8);
          e20.emitAndNotify("moveout");
          for (var t15 = 0; t15 < n11.length; t15++) {
            var i10 = n11[t15], o12 = i10._private.data;
            i10.isNode() && (o12.parent = d10);
          }
          e20.restore(r8, a8);
        }), n11.emitAndNotify("move");
      }
    }
    return this;
  }, [Zn, cr3, dr2, Ur, Jr, oa, sa, za, Ua, Za, { isNode: function() {
    return "nodes" === this.group();
  }, isEdge: function() {
    return "edges" === this.group();
  }, isLoop: function() {
    return this.isEdge() && this.source()[0] === this.target()[0];
  }, isSimple: function() {
    return this.isEdge() && this.source()[0] !== this.target()[0];
  }, group: function() {
    var e19 = this[0];
    if (e19)
      return e19._private.group;
  } }, Ja, ni, oi, fi, yi].forEach(function(e19) {
    J4(Si, e19);
  });
  var Di = { add: function(e19) {
    var t14, n11 = this;
    if (L5(e19)) {
      var r8 = e19;
      if (r8._private.cy === n11)
        t14 = r8.restore();
      else {
        for (var a8 = [], i9 = 0; i9 < r8.length; i9++) {
          var o11 = r8[i9];
          a8.push(o11.json());
        }
        t14 = new Ci(n11, a8);
      }
    } else if (_5(e19)) {
      t14 = new Ci(n11, e19);
    } else if (N6(e19) && (_5(e19.nodes) || _5(e19.edges))) {
      for (var s10 = e19, l10 = [], u9 = ["nodes", "edges"], c9 = 0, d10 = u9.length; c9 < d10; c9++) {
        var h9 = u9[c9], p9 = s10[h9];
        if (_5(p9))
          for (var f10 = 0, g8 = p9.length; f10 < g8; f10++) {
            var v11 = J4({ group: h9 }, p9[f10]);
            l10.push(v11);
          }
      }
      t14 = new Ci(n11, l10);
    } else {
      t14 = new je(n11, e19).collection();
    }
    return t14;
  }, remove: function(e19) {
    if (L5(e19))
      ;
    else if (M6(e19)) {
      var t14 = e19;
      e19 = this.$(t14);
    }
    return e19.remove();
  } };
  function Pi(e19, t14, n11, r8) {
    var a8 = 4, i9 = 1e-7, o11 = 10, s10 = 11, l10 = 1 / (s10 - 1), u9 = "undefined" != typeof Float32Array;
    if (4 !== arguments.length)
      return false;
    for (var c9 = 0; c9 < 4; ++c9)
      if ("number" != typeof arguments[c9] || isNaN(arguments[c9]) || !isFinite(arguments[c9]))
        return false;
    e19 = Math.min(e19, 1), n11 = Math.min(n11, 1), e19 = Math.max(e19, 0), n11 = Math.max(n11, 0);
    var d10 = u9 ? new Float32Array(s10) : new Array(s10);
    function h9(e20, t15) {
      return 1 - 3 * t15 + 3 * e20;
    }
    function p9(e20, t15) {
      return 3 * t15 - 6 * e20;
    }
    function f10(e20) {
      return 3 * e20;
    }
    function g8(e20, t15, n12) {
      return ((h9(t15, n12) * e20 + p9(t15, n12)) * e20 + f10(t15)) * e20;
    }
    function v11(e20, t15, n12) {
      return 3 * h9(t15, n12) * e20 * e20 + 2 * p9(t15, n12) * e20 + f10(t15);
    }
    function y9(t15) {
      for (var r9 = 0, u10 = 1, c10 = s10 - 1; u10 !== c10 && d10[u10] <= t15; ++u10)
        r9 += l10;
      --u10;
      var h10 = r9 + (t15 - d10[u10]) / (d10[u10 + 1] - d10[u10]) * l10, p10 = v11(h10, e19, n11);
      return p10 >= 1e-3 ? function(t16, r10) {
        for (var i10 = 0; i10 < a8; ++i10) {
          var o12 = v11(r10, e19, n11);
          if (0 === o12)
            return r10;
          r10 -= (g8(r10, e19, n11) - t16) / o12;
        }
        return r10;
      }(t15, h10) : 0 === p10 ? h10 : function(t16, r10, a9) {
        var s11, l11, u11 = 0;
        do {
          (s11 = g8(l11 = r10 + (a9 - r10) / 2, e19, n11) - t16) > 0 ? a9 = l11 : r10 = l11;
        } while (Math.abs(s11) > i9 && ++u11 < o11);
        return l11;
      }(t15, r9, r9 + l10);
    }
    var m11 = false;
    function b10() {
      m11 = true, e19 === t14 && n11 === r8 || function() {
        for (var t15 = 0; t15 < s10; ++t15)
          d10[t15] = g8(t15 * l10, e19, n11);
      }();
    }
    var x10 = function(a9) {
      return m11 || b10(), e19 === t14 && n11 === r8 ? a9 : 0 === a9 ? 0 : 1 === a9 ? 1 : g8(y9(a9), t14, r8);
    };
    x10.getControlPoints = function() {
      return [{ x: e19, y: t14 }, { x: n11, y: r8 }];
    };
    var w9 = "generateBezier(" + [e19, t14, n11, r8] + ")";
    return x10.toString = function() {
      return w9;
    }, x10;
  }
  var Ti = function() {
    function e19(e20) {
      return -e20.tension * e20.x - e20.friction * e20.v;
    }
    function t14(t15, n12, r8) {
      var a8 = { x: t15.x + r8.dx * n12, v: t15.v + r8.dv * n12, tension: t15.tension, friction: t15.friction };
      return { dx: a8.v, dv: e19(a8) };
    }
    function n11(n12, r8) {
      var a8 = { dx: n12.v, dv: e19(n12) }, i9 = t14(n12, 0.5 * r8, a8), o11 = t14(n12, 0.5 * r8, i9), s10 = t14(n12, r8, o11), l10 = 1 / 6 * (a8.dx + 2 * (i9.dx + o11.dx) + s10.dx), u9 = 1 / 6 * (a8.dv + 2 * (i9.dv + o11.dv) + s10.dv);
      return n12.x = n12.x + l10 * r8, n12.v = n12.v + u9 * r8, n12;
    }
    return function e20(t15, r8, a8) {
      var i9, o11, s10, l10 = { x: -1, v: 0, tension: null, friction: null }, u9 = [0], c9 = 0, d10 = 1e-4;
      for (t15 = parseFloat(t15) || 500, r8 = parseFloat(r8) || 20, a8 = a8 || null, l10.tension = t15, l10.friction = r8, o11 = (i9 = null !== a8) ? (c9 = e20(t15, r8)) / a8 * 0.016 : 0.016; s10 = n11(s10 || l10, o11), u9.push(1 + s10.x), c9 += 16, Math.abs(s10.x) > d10 && Math.abs(s10.v) > d10; )
        ;
      return i9 ? function(e21) {
        return u9[e21 * (u9.length - 1) | 0];
      } : c9;
    };
  }();
  var Mi = function(e19, t14, n11, r8) {
    var a8 = Pi(e19, t14, n11, r8);
    return function(e20, t15, n12) {
      return e20 + (t15 - e20) * a8(n12);
    };
  };
  var Bi = { linear: function(e19, t14, n11) {
    return e19 + (t14 - e19) * n11;
  }, ease: Mi(0.25, 0.1, 0.25, 1), "ease-in": Mi(0.42, 0, 1, 1), "ease-out": Mi(0, 0, 0.58, 1), "ease-in-out": Mi(0.42, 0, 0.58, 1), "ease-in-sine": Mi(0.47, 0, 0.745, 0.715), "ease-out-sine": Mi(0.39, 0.575, 0.565, 1), "ease-in-out-sine": Mi(0.445, 0.05, 0.55, 0.95), "ease-in-quad": Mi(0.55, 0.085, 0.68, 0.53), "ease-out-quad": Mi(0.25, 0.46, 0.45, 0.94), "ease-in-out-quad": Mi(0.455, 0.03, 0.515, 0.955), "ease-in-cubic": Mi(0.55, 0.055, 0.675, 0.19), "ease-out-cubic": Mi(0.215, 0.61, 0.355, 1), "ease-in-out-cubic": Mi(0.645, 0.045, 0.355, 1), "ease-in-quart": Mi(0.895, 0.03, 0.685, 0.22), "ease-out-quart": Mi(0.165, 0.84, 0.44, 1), "ease-in-out-quart": Mi(0.77, 0, 0.175, 1), "ease-in-quint": Mi(0.755, 0.05, 0.855, 0.06), "ease-out-quint": Mi(0.23, 1, 0.32, 1), "ease-in-out-quint": Mi(0.86, 0, 0.07, 1), "ease-in-expo": Mi(0.95, 0.05, 0.795, 0.035), "ease-out-expo": Mi(0.19, 1, 0.22, 1), "ease-in-out-expo": Mi(1, 0, 0, 1), "ease-in-circ": Mi(0.6, 0.04, 0.98, 0.335), "ease-out-circ": Mi(0.075, 0.82, 0.165, 1), "ease-in-out-circ": Mi(0.785, 0.135, 0.15, 0.86), spring: function(e19, t14, n11) {
    if (0 === n11)
      return Bi.linear;
    var r8 = Ti(e19, t14, n11);
    return function(e20, t15, n12) {
      return e20 + (t15 - e20) * r8(n12);
    };
  }, "cubic-bezier": Mi };
  function _i(e19, t14, n11, r8, a8) {
    if (1 === r8)
      return n11;
    if (t14 === n11)
      return n11;
    var i9 = a8(t14, n11, r8);
    return null == e19 || ((e19.roundValue || e19.color) && (i9 = Math.round(i9)), void 0 !== e19.min && (i9 = Math.max(i9, e19.min)), void 0 !== e19.max && (i9 = Math.min(i9, e19.max))), i9;
  }
  function Ni(e19, t14) {
    return null != e19.pfValue || null != e19.value ? null == e19.pfValue || null != t14 && "%" === t14.type.units ? e19.value : e19.pfValue : e19;
  }
  function Ii(e19, t14, n11, r8, a8) {
    var i9 = null != a8 ? a8.type : null;
    n11 < 0 ? n11 = 0 : n11 > 1 && (n11 = 1);
    var o11 = Ni(e19, a8), s10 = Ni(t14, a8);
    if (I6(o11) && I6(s10))
      return _i(i9, o11, s10, n11, r8);
    if (_5(o11) && _5(s10)) {
      for (var l10 = [], u9 = 0; u9 < s10.length; u9++) {
        var c9 = o11[u9], d10 = s10[u9];
        if (null != c9 && null != d10) {
          var h9 = _i(i9, c9, d10, n11, r8);
          l10.push(h9);
        } else
          l10.push(d10);
      }
      return l10;
    }
  }
  function zi(e19, t14, n11, r8) {
    var a8 = !r8, i9 = e19._private, o11 = t14._private, s10 = o11.easing, l10 = o11.startTime, u9 = (r8 ? e19 : e19.cy()).style();
    if (!o11.easingImpl)
      if (null == s10)
        o11.easingImpl = Bi.linear;
      else {
        var c9, d10, h9;
        if (M6(s10))
          c9 = u9.parse("transition-timing-function", s10).value;
        else
          c9 = s10;
        M6(c9) ? (d10 = c9, h9 = []) : (d10 = c9[1], h9 = c9.slice(2).map(function(e20) {
          return +e20;
        })), h9.length > 0 ? ("spring" === d10 && h9.push(o11.duration), o11.easingImpl = Bi[d10].apply(null, h9)) : o11.easingImpl = Bi[d10];
      }
    var p9, f10 = o11.easingImpl;
    if (p9 = 0 === o11.duration ? 1 : (n11 - l10) / o11.duration, o11.applying && (p9 = o11.progress), p9 < 0 ? p9 = 0 : p9 > 1 && (p9 = 1), null == o11.delay) {
      var g8 = o11.startPosition, v11 = o11.position;
      if (v11 && a8 && !e19.locked()) {
        var y9 = {};
        Li(g8.x, v11.x) && (y9.x = Ii(g8.x, v11.x, p9, f10)), Li(g8.y, v11.y) && (y9.y = Ii(g8.y, v11.y, p9, f10)), e19.position(y9);
      }
      var m11 = o11.startPan, b10 = o11.pan, x10 = i9.pan, w9 = null != b10 && r8;
      w9 && (Li(m11.x, b10.x) && (x10.x = Ii(m11.x, b10.x, p9, f10)), Li(m11.y, b10.y) && (x10.y = Ii(m11.y, b10.y, p9, f10)), e19.emit("pan"));
      var E8 = o11.startZoom, k9 = o11.zoom, C8 = null != k9 && r8;
      C8 && (Li(E8, k9) && (i9.zoom = gt4(i9.minZoom, Ii(E8, k9, p9, f10), i9.maxZoom)), e19.emit("zoom")), (w9 || C8) && e19.emit("viewport");
      var S7 = o11.style;
      if (S7 && S7.length > 0 && a8) {
        for (var D7 = 0; D7 < S7.length; D7++) {
          var P9 = S7[D7], T8 = P9.name, B8 = P9, _6 = o11.startStyle[T8], N7 = Ii(_6, B8, p9, f10, u9.properties[_6.name]);
          u9.overrideBypass(e19, T8, N7);
        }
        e19.emit("style");
      }
    }
    return o11.progress = p9, p9;
  }
  function Li(e19, t14) {
    return null != e19 && null != t14 && (!(!I6(e19) || !I6(t14)) || !(!e19 || !t14));
  }
  function Ai(e19, t14, n11, r8) {
    var a8 = t14._private;
    a8.started = true, a8.startTime = n11 - a8.progress * a8.duration;
  }
  function Oi(e19, t14) {
    var n11 = t14._private.aniEles, r8 = [];
    function a8(t15, n12) {
      var a9 = t15._private, i10 = a9.animation.current, o12 = a9.animation.queue, s11 = false;
      if (0 === i10.length) {
        var l11 = o12.shift();
        l11 && i10.push(l11);
      }
      for (var u9 = function(e20) {
        for (var t16 = e20.length - 1; t16 >= 0; t16--) {
          (0, e20[t16])();
        }
        e20.splice(0, e20.length);
      }, c9 = i10.length - 1; c9 >= 0; c9--) {
        var d10 = i10[c9], h9 = d10._private;
        h9.stopped ? (i10.splice(c9, 1), h9.hooked = false, h9.playing = false, h9.started = false, u9(h9.frames)) : (h9.playing || h9.applying) && (h9.playing && h9.applying && (h9.applying = false), h9.started || Ai(0, d10, e19), zi(t15, d10, e19, n12), h9.applying && (h9.applying = false), u9(h9.frames), null != h9.step && h9.step(e19), d10.completed() && (i10.splice(c9, 1), h9.hooked = false, h9.playing = false, h9.started = false, u9(h9.completes)), s11 = true);
      }
      return n12 || 0 !== i10.length || 0 !== o12.length || r8.push(t15), s11;
    }
    for (var i9 = false, o11 = 0; o11 < n11.length; o11++) {
      var s10 = a8(n11[o11]);
      i9 = i9 || s10;
    }
    var l10 = a8(t14, true);
    (i9 || l10) && (n11.length > 0 ? t14.notify("draw", n11) : t14.notify("draw")), n11.unmerge(r8), t14.emit("step");
  }
  var Ri = { animate: ur3.animate(), animation: ur3.animation(), animated: ur3.animated(), clearQueue: ur3.clearQueue(), delay: ur3.delay(), delayAnimation: ur3.delayAnimation(), stop: ur3.stop(), addToAnimationPool: function(e19) {
    this.styleEnabled() && this._private.aniEles.merge(e19);
  }, stopAnimationLoop: function() {
    this._private.animationsRunning = false;
  }, startAnimationLoop: function() {
    var e19 = this;
    if (e19._private.animationsRunning = true, e19.styleEnabled()) {
      var t14 = e19.renderer();
      t14 && t14.beforeRender ? t14.beforeRender(function(t15, n11) {
        Oi(n11, e19);
      }, t14.beforeRenderPriorities.animations) : function t15() {
        e19._private.animationsRunning && se(function(n11) {
          Oi(n11, e19), t15();
        });
      }();
    }
  } };
  var Vi = { qualifierCompare: function(e19, t14) {
    return null == e19 || null == t14 ? null == e19 && null == t14 : e19.sameText(t14);
  }, eventMatches: function(e19, t14, n11) {
    var r8 = t14.qualifier;
    return null == r8 || e19 !== n11.target && A6(n11.target) && r8.matches(n11.target);
  }, addEventFields: function(e19, t14) {
    t14.cy = e19, t14.target = e19;
  }, callbackContext: function(e19, t14, n11) {
    return null != t14.qualifier ? n11.target : e19;
  } };
  var Fi = function(e19) {
    return M6(e19) ? new Kr(e19) : e19;
  };
  var qi = { createEmitter: function() {
    var e19 = this._private;
    return e19.emitter || (e19.emitter = new ja(Vi, this)), this;
  }, emitter: function() {
    return this._private.emitter;
  }, on: function(e19, t14, n11) {
    return this.emitter().on(e19, Fi(t14), n11), this;
  }, removeListener: function(e19, t14, n11) {
    return this.emitter().removeListener(e19, Fi(t14), n11), this;
  }, removeAllListeners: function() {
    return this.emitter().removeAllListeners(), this;
  }, one: function(e19, t14, n11) {
    return this.emitter().one(e19, Fi(t14), n11), this;
  }, once: function(e19, t14, n11) {
    return this.emitter().one(e19, Fi(t14), n11), this;
  }, emit: function(e19, t14) {
    return this.emitter().emit(e19, t14), this;
  }, emitAndNotify: function(e19, t14) {
    return this.emit(e19), this.notify(e19, t14), this;
  } };
  ur3.eventAliasesOn(qi);
  var ji = { png: function(e19) {
    return e19 = e19 || {}, this._private.renderer.png(e19);
  }, jpg: function(e19) {
    var t14 = this._private.renderer;
    return (e19 = e19 || {}).bg = e19.bg || "#fff", t14.jpg(e19);
  } };
  ji.jpeg = ji.jpg;
  var Yi = { layout: function(e19) {
    var t14 = this;
    if (null != e19)
      if (null != e19.name) {
        var n11 = e19.name, r8 = t14.extension("layout", n11);
        if (null != r8) {
          var a8;
          a8 = M6(e19.eles) ? t14.$(e19.eles) : null != e19.eles ? e19.eles : t14.$();
          var i9 = new r8(J4({}, e19, { cy: t14, eles: a8 }));
          return i9;
        }
        Pe("No such layout `" + n11 + "` found.  Did you forget to import it and `cytoscape.use()` it?");
      } else
        Pe("A `name` must be specified to make a layout");
    else
      Pe("Layout options must be specified to make a layout");
  } };
  Yi.createLayout = Yi.makeLayout = Yi.layout;
  var Xi = { notify: function(e19, t14) {
    var n11 = this._private;
    if (this.batching()) {
      n11.batchNotifications = n11.batchNotifications || {};
      var r8 = n11.batchNotifications[e19] = n11.batchNotifications[e19] || this.collection();
      null != t14 && r8.merge(t14);
    } else if (n11.notificationsEnabled) {
      var a8 = this.renderer();
      !this.destroyed() && a8 && a8.notify(e19, t14);
    }
  }, notifications: function(e19) {
    var t14 = this._private;
    return void 0 === e19 ? t14.notificationsEnabled : (t14.notificationsEnabled = !!e19, this);
  }, noNotifications: function(e19) {
    this.notifications(false), e19(), this.notifications(true);
  }, batching: function() {
    return this._private.batchCount > 0;
  }, startBatch: function() {
    var e19 = this._private;
    return null == e19.batchCount && (e19.batchCount = 0), 0 === e19.batchCount && (e19.batchStyleEles = this.collection(), e19.batchNotifications = {}), e19.batchCount++, this;
  }, endBatch: function() {
    var e19 = this._private;
    if (0 === e19.batchCount)
      return this;
    if (e19.batchCount--, 0 === e19.batchCount) {
      e19.batchStyleEles.updateStyle();
      var t14 = this.renderer();
      Object.keys(e19.batchNotifications).forEach(function(n11) {
        var r8 = e19.batchNotifications[n11];
        r8.empty() ? t14.notify(n11) : t14.notify(n11, r8);
      });
    }
    return this;
  }, batch: function(e19) {
    return this.startBatch(), e19(), this.endBatch(), this;
  }, batchData: function(e19) {
    var t14 = this;
    return this.batch(function() {
      for (var n11 = Object.keys(e19), r8 = 0; r8 < n11.length; r8++) {
        var a8 = n11[r8], i9 = e19[a8];
        t14.getElementById(a8).data(i9);
      }
    });
  } };
  var Wi = ze({ hideEdgesOnViewport: false, textureOnViewport: false, motionBlur: false, motionBlurOpacity: 0.05, pixelRatio: void 0, desktopTapThreshold: 4, touchTapThreshold: 8, wheelSensitivity: 1, debug: false, showFps: false });
  var Hi = { renderTo: function(e19, t14, n11, r8) {
    return this._private.renderer.renderTo(e19, t14, n11, r8), this;
  }, renderer: function() {
    return this._private.renderer;
  }, forceRender: function() {
    return this.notify("draw"), this;
  }, resize: function() {
    return this.invalidateSize(), this.emitAndNotify("resize"), this;
  }, initRenderer: function(e19) {
    var t14 = this, n11 = t14.extension("renderer", e19.name);
    if (null != n11) {
      void 0 !== e19.wheelSensitivity && Me("You have set a custom wheel sensitivity.  This will make your app zoom unnaturally when using mainstream mice.  You should change this value from the default only if you can guarantee that all your users will use the same hardware and OS configuration as your current machine.");
      var r8 = Wi(e19);
      r8.cy = t14, t14._private.renderer = new n11(r8), this.notify("init");
    } else
      Pe("Can not initialise: No such renderer `".concat(e19.name, "` found. Did you forget to import it and `cytoscape.use()` it?"));
  }, destroyRenderer: function() {
    var e19 = this;
    e19.notify("destroy");
    var t14 = e19.container();
    if (t14)
      for (t14._cyreg = null; t14.childNodes.length > 0; )
        t14.removeChild(t14.childNodes[0]);
    e19._private.renderer = null, e19.mutableElements().forEach(function(e20) {
      var t15 = e20._private;
      t15.rscratch = {}, t15.rstyle = {}, t15.animation.current = [], t15.animation.queue = [];
    });
  }, onRender: function(e19) {
    return this.on("render", e19);
  }, offRender: function(e19) {
    return this.off("render", e19);
  } };
  Hi.invalidateDimensions = Hi.resize;
  var Ki = { collection: function(e19, t14) {
    return M6(e19) ? this.$(e19) : L5(e19) ? e19.collection() : _5(e19) ? (t14 || (t14 = {}), new Ci(this, e19, t14.unique, t14.removed)) : new Ci(this);
  }, nodes: function(e19) {
    var t14 = this.$(function(e20) {
      return e20.isNode();
    });
    return e19 ? t14.filter(e19) : t14;
  }, edges: function(e19) {
    var t14 = this.$(function(e20) {
      return e20.isEdge();
    });
    return e19 ? t14.filter(e19) : t14;
  }, $: function(e19) {
    var t14 = this._private.elements;
    return e19 ? t14.filter(e19) : t14.spawnSelf();
  }, mutableElements: function() {
    return this._private.elements;
  } };
  Ki.elements = Ki.filter = Ki.$;
  var Gi = {};
  var Ui = "t";
  Gi.apply = function(e19) {
    for (var t14 = this, n11 = t14._private.cy.collection(), r8 = 0; r8 < e19.length; r8++) {
      var a8 = e19[r8], i9 = t14.getContextMeta(a8);
      if (!i9.empty) {
        var o11 = t14.getContextStyle(i9), s10 = t14.applyContextStyle(i9, o11, a8);
        a8._private.appliedInitStyle ? t14.updateTransitions(a8, s10.diffProps) : a8._private.appliedInitStyle = true, t14.updateStyleHints(a8) && n11.push(a8);
      }
    }
    return n11;
  }, Gi.getPropertiesDiff = function(e19, t14) {
    var n11 = this, r8 = n11._private.propDiffs = n11._private.propDiffs || {}, a8 = e19 + "-" + t14, i9 = r8[a8];
    if (i9)
      return i9;
    for (var o11 = [], s10 = {}, l10 = 0; l10 < n11.length; l10++) {
      var u9 = n11[l10], c9 = e19[l10] === Ui, d10 = t14[l10] === Ui, h9 = c9 !== d10, p9 = u9.mappedProperties.length > 0;
      if (h9 || d10 && p9) {
        var f10 = void 0;
        h9 && p9 || h9 ? f10 = u9.properties : p9 && (f10 = u9.mappedProperties);
        for (var g8 = 0; g8 < f10.length; g8++) {
          for (var v11 = f10[g8], y9 = v11.name, m11 = false, b10 = l10 + 1; b10 < n11.length; b10++) {
            var x10 = n11[b10];
            if (t14[b10] === Ui && (m11 = null != x10.properties[v11.name]))
              break;
          }
          s10[y9] || m11 || (s10[y9] = true, o11.push(y9));
        }
      }
    }
    return r8[a8] = o11, o11;
  }, Gi.getContextMeta = function(e19) {
    for (var t14, n11 = this, r8 = "", a8 = e19._private.styleCxtKey || "", i9 = 0; i9 < n11.length; i9++) {
      var o11 = n11[i9];
      r8 += o11.selector && o11.selector.matches(e19) ? Ui : "f";
    }
    return t14 = n11.getPropertiesDiff(a8, r8), e19._private.styleCxtKey = r8, { key: r8, diffPropNames: t14, empty: 0 === t14.length };
  }, Gi.getContextStyle = function(e19) {
    var t14 = e19.key, n11 = this._private.contextStyles = this._private.contextStyles || {};
    if (n11[t14])
      return n11[t14];
    for (var r8 = { _private: { key: t14 } }, a8 = 0; a8 < this.length; a8++) {
      var i9 = this[a8];
      if (t14[a8] === Ui)
        for (var o11 = 0; o11 < i9.properties.length; o11++) {
          var s10 = i9.properties[o11];
          r8[s10.name] = s10;
        }
    }
    return n11[t14] = r8, r8;
  }, Gi.applyContextStyle = function(e19, t14, n11) {
    for (var r8 = e19.diffPropNames, a8 = {}, i9 = this.types, o11 = 0; o11 < r8.length; o11++) {
      var s10 = r8[o11], l10 = t14[s10], u9 = n11.pstyle(s10);
      if (!l10) {
        if (!u9)
          continue;
        l10 = u9.bypass ? { name: s10, deleteBypassed: true } : { name: s10, delete: true };
      }
      if (u9 !== l10) {
        if (l10.mapped === i9.fn && null != u9 && null != u9.mapping && u9.mapping.value === l10.value) {
          var c9 = u9.mapping;
          if ((c9.fnValue = l10.value(n11)) === c9.prevFnValue)
            continue;
        }
        var d10 = a8[s10] = { prev: u9 };
        this.applyParsedProperty(n11, l10), d10.next = n11.pstyle(s10), d10.next && d10.next.bypass && (d10.next = d10.next.bypassed);
      }
    }
    return { diffProps: a8 };
  }, Gi.updateStyleHints = function(e19) {
    var t14 = e19._private, n11 = this, r8 = n11.propertyGroupNames, a8 = n11.propertyGroupKeys, i9 = function(e20, t15, r9) {
      return n11.getPropertiesHash(e20, t15, r9);
    }, o11 = t14.styleKey;
    if (e19.removed())
      return false;
    var s10 = "nodes" === t14.group, l10 = e19._private.style;
    r8 = Object.keys(l10);
    for (var u9 = 0; u9 < a8.length; u9++) {
      var c9 = a8[u9];
      t14.styleKeys[c9] = [ue, ce];
    }
    for (var d10, h9 = function(e20, n12) {
      return t14.styleKeys[n12][0] = he(e20, t14.styleKeys[n12][0]);
    }, p9 = function(e20, n12) {
      return t14.styleKeys[n12][1] = pe(e20, t14.styleKeys[n12][1]);
    }, f10 = function(e20, t15) {
      h9(e20, t15), p9(e20, t15);
    }, g8 = function(e20, t15) {
      for (var n12 = 0; n12 < e20.length; n12++) {
        var r9 = e20.charCodeAt(n12);
        h9(r9, t15), p9(r9, t15);
      }
    }, v11 = 0; v11 < r8.length; v11++) {
      var y9 = r8[v11], m11 = l10[y9];
      if (null != m11) {
        var b10 = this.properties[y9], x10 = b10.type, w9 = b10.groupKey, E8 = void 0;
        null != b10.hashOverride ? E8 = b10.hashOverride(e19, m11) : null != m11.pfValue && (E8 = m11.pfValue);
        var k9 = null == b10.enums ? m11.value : null, C8 = null != E8, S7 = C8 || null != k9, D7 = m11.units;
        if (x10.number && S7 && !x10.multiple)
          f10(-128 < (d10 = C8 ? E8 : k9) && d10 < 128 && Math.floor(d10) !== d10 ? 2e9 - (1024 * d10 | 0) : d10, w9), C8 || null == D7 || g8(D7, w9);
        else
          g8(m11.strValue, w9);
      }
    }
    for (var P9, T8, M8 = [ue, ce], B8 = 0; B8 < a8.length; B8++) {
      var _6 = a8[B8], N7 = t14.styleKeys[_6];
      M8[0] = he(N7[0], M8[0]), M8[1] = pe(N7[1], M8[1]);
    }
    t14.styleKey = (P9 = M8[0], T8 = M8[1], 2097152 * P9 + T8);
    var I7 = t14.styleKeys;
    t14.labelDimsKey = fe(I7.labelDimensions);
    var z7 = i9(e19, ["label"], I7.labelDimensions);
    if (t14.labelKey = fe(z7), t14.labelStyleKey = fe(ge(I7.commonLabel, z7)), !s10) {
      var L9 = i9(e19, ["source-label"], I7.labelDimensions);
      t14.sourceLabelKey = fe(L9), t14.sourceLabelStyleKey = fe(ge(I7.commonLabel, L9));
      var A9 = i9(e19, ["target-label"], I7.labelDimensions);
      t14.targetLabelKey = fe(A9), t14.targetLabelStyleKey = fe(ge(I7.commonLabel, A9));
    }
    if (s10) {
      var O8 = t14.styleKeys, R7 = O8.nodeBody, V6 = O8.nodeBorder, F7 = O8.backgroundImage, q7 = O8.compound, j8 = O8.pie, Y5 = [R7, V6, F7, q7, j8].filter(function(e20) {
        return null != e20;
      }).reduce(ge, [ue, ce]);
      t14.nodeKey = fe(Y5), t14.hasPie = null != j8 && j8[0] !== ue && j8[1] !== ce;
    }
    return o11 !== t14.styleKey;
  }, Gi.clearStyleHints = function(e19) {
    var t14 = e19._private;
    t14.styleCxtKey = "", t14.styleKeys = {}, t14.styleKey = null, t14.labelKey = null, t14.labelStyleKey = null, t14.sourceLabelKey = null, t14.sourceLabelStyleKey = null, t14.targetLabelKey = null, t14.targetLabelStyleKey = null, t14.nodeKey = null, t14.hasPie = null;
  }, Gi.applyParsedProperty = function(e19, t14) {
    var n11, r8 = this, a8 = t14, i9 = e19._private.style, o11 = r8.types, s10 = r8.properties[a8.name].type, l10 = a8.bypass, u9 = i9[a8.name], c9 = u9 && u9.bypass, d10 = e19._private, h9 = "mapping", p9 = function(e20) {
      return null == e20 ? null : null != e20.pfValue ? e20.pfValue : e20.value;
    }, f10 = function() {
      var t15 = p9(u9), n12 = p9(a8);
      r8.checkTriggers(e19, a8.name, t15, n12);
    };
    if (a8 && "pie" === a8.name.substr(0, 3) && Me("The pie style properties are deprecated.  Create charts using background images instead."), "curve-style" === t14.name && e19.isEdge() && ("bezier" !== t14.value && e19.isLoop() || "haystack" === t14.value && (e19.source().isParent() || e19.target().isParent())) && (a8 = t14 = this.parse(t14.name, "bezier", l10)), a8.delete)
      return i9[a8.name] = void 0, f10(), true;
    if (a8.deleteBypassed)
      return u9 ? !!u9.bypass && (u9.bypassed = void 0, f10(), true) : (f10(), true);
    if (a8.deleteBypass)
      return u9 ? !!u9.bypass && (i9[a8.name] = u9.bypassed, f10(), true) : (f10(), true);
    var g8 = function() {
      Me("Do not assign mappings to elements without corresponding data (i.e. ele `" + e19.id() + "` has no mapping for property `" + a8.name + "` with data field `" + a8.field + "`); try a `[" + a8.field + "]` selector to limit scope to elements with `" + a8.field + "` defined");
    };
    switch (a8.mapped) {
      case o11.mapData:
        for (var v11, y9 = a8.field.split("."), m11 = d10.data, b10 = 0; b10 < y9.length && m11; b10++) {
          m11 = m11[y9[b10]];
        }
        if (null == m11)
          return g8(), false;
        if (!I6(m11))
          return Me("Do not use continuous mappers without specifying numeric data (i.e. `" + a8.field + ": " + m11 + "` for `" + e19.id() + "` is non-numeric)"), false;
        var x10 = a8.fieldMax - a8.fieldMin;
        if ((v11 = 0 === x10 ? 0 : (m11 - a8.fieldMin) / x10) < 0 ? v11 = 0 : v11 > 1 && (v11 = 1), s10.color) {
          var w9 = a8.valueMin[0], E8 = a8.valueMax[0], k9 = a8.valueMin[1], C8 = a8.valueMax[1], S7 = a8.valueMin[2], D7 = a8.valueMax[2], P9 = null == a8.valueMin[3] ? 1 : a8.valueMin[3], T8 = null == a8.valueMax[3] ? 1 : a8.valueMax[3], M8 = [Math.round(w9 + (E8 - w9) * v11), Math.round(k9 + (C8 - k9) * v11), Math.round(S7 + (D7 - S7) * v11), Math.round(P9 + (T8 - P9) * v11)];
          n11 = { bypass: a8.bypass, name: a8.name, value: M8, strValue: "rgb(" + M8[0] + ", " + M8[1] + ", " + M8[2] + ")" };
        } else {
          if (!s10.number)
            return false;
          var B8 = a8.valueMin + (a8.valueMax - a8.valueMin) * v11;
          n11 = this.parse(a8.name, B8, a8.bypass, h9);
        }
        if (!n11)
          return g8(), false;
        n11.mapping = a8, a8 = n11;
        break;
      case o11.data:
        for (var _6 = a8.field.split("."), N7 = d10.data, z7 = 0; z7 < _6.length && N7; z7++) {
          N7 = N7[_6[z7]];
        }
        if (null != N7 && (n11 = this.parse(a8.name, N7, a8.bypass, h9)), !n11)
          return g8(), false;
        n11.mapping = a8, a8 = n11;
        break;
      case o11.fn:
        var L9 = a8.value, A9 = null != a8.fnValue ? a8.fnValue : L9(e19);
        if (a8.prevFnValue = A9, null == A9)
          return Me("Custom function mappers may not return null (i.e. `" + a8.name + "` for ele `" + e19.id() + "` is null)"), false;
        if (!(n11 = this.parse(a8.name, A9, a8.bypass, h9)))
          return Me("Custom function mappers may not return invalid values for the property type (i.e. `" + a8.name + "` for ele `" + e19.id() + "` is invalid)"), false;
        n11.mapping = Be(a8), a8 = n11;
        break;
      case void 0:
        break;
      default:
        return false;
    }
    return l10 ? (a8.bypassed = c9 ? u9.bypassed : u9, i9[a8.name] = a8) : c9 ? u9.bypassed = a8 : i9[a8.name] = a8, f10(), true;
  }, Gi.cleanElements = function(e19, t14) {
    for (var n11 = 0; n11 < e19.length; n11++) {
      var r8 = e19[n11];
      if (this.clearStyleHints(r8), r8.dirtyCompoundBoundsCache(), r8.dirtyBoundingBoxCache(), t14)
        for (var a8 = r8._private.style, i9 = Object.keys(a8), o11 = 0; o11 < i9.length; o11++) {
          var s10 = i9[o11], l10 = a8[s10];
          null != l10 && (l10.bypass ? l10.bypassed = null : a8[s10] = null);
        }
      else
        r8._private.style = {};
    }
  }, Gi.update = function() {
    this._private.cy.mutableElements().updateStyle();
  }, Gi.updateTransitions = function(e19, t14) {
    var n11 = this, r8 = e19._private, a8 = e19.pstyle("transition-property").value, i9 = e19.pstyle("transition-duration").pfValue, o11 = e19.pstyle("transition-delay").pfValue;
    if (a8.length > 0 && i9 > 0) {
      for (var s10 = {}, l10 = false, u9 = 0; u9 < a8.length; u9++) {
        var c9 = a8[u9], d10 = e19.pstyle(c9), h9 = t14[c9];
        if (h9) {
          var p9 = h9.prev, f10 = null != h9.next ? h9.next : d10, g8 = false, v11 = void 0, y9 = 1e-6;
          p9 && (I6(p9.pfValue) && I6(f10.pfValue) ? (g8 = f10.pfValue - p9.pfValue, v11 = p9.pfValue + y9 * g8) : I6(p9.value) && I6(f10.value) ? (g8 = f10.value - p9.value, v11 = p9.value + y9 * g8) : _5(p9.value) && _5(f10.value) && (g8 = p9.value[0] !== f10.value[0] || p9.value[1] !== f10.value[1] || p9.value[2] !== f10.value[2], v11 = p9.strValue), g8 && (s10[c9] = f10.strValue, this.applyBypass(e19, c9, v11), l10 = true));
        }
      }
      if (!l10)
        return;
      r8.transitioning = true, new rr4(function(t15) {
        o11 > 0 ? e19.delayAnimation(o11).play().promise().then(t15) : t15();
      }).then(function() {
        return e19.animation({ style: s10, duration: i9, easing: e19.pstyle("transition-timing-function").value, queue: false }).play().promise();
      }).then(function() {
        n11.removeBypasses(e19, a8), e19.emitAndNotify("style"), r8.transitioning = false;
      });
    } else
      r8.transitioning && (this.removeBypasses(e19, a8), e19.emitAndNotify("style"), r8.transitioning = false);
  }, Gi.checkTrigger = function(e19, t14, n11, r8, a8, i9) {
    var o11 = this.properties[t14], s10 = a8(o11);
    null != s10 && s10(n11, r8) && i9(o11);
  }, Gi.checkZOrderTrigger = function(e19, t14, n11, r8) {
    var a8 = this;
    this.checkTrigger(e19, t14, n11, r8, function(e20) {
      return e20.triggersZOrder;
    }, function() {
      a8._private.cy.notify("zorder", e19);
    });
  }, Gi.checkBoundsTrigger = function(e19, t14, n11, r8) {
    this.checkTrigger(e19, t14, n11, r8, function(e20) {
      return e20.triggersBounds;
    }, function(a8) {
      e19.dirtyCompoundBoundsCache(), e19.dirtyBoundingBoxCache(), !a8.triggersBoundsOfParallelBeziers || ("curve-style" !== t14 || "bezier" !== n11 && "bezier" !== r8) && ("display" !== t14 || "none" !== n11 && "none" !== r8) || e19.parallelEdges().forEach(function(e20) {
        e20.isBundledBezier() && e20.dirtyBoundingBoxCache();
      });
    });
  }, Gi.checkTriggers = function(e19, t14, n11, r8) {
    e19.dirtyStyleCache(), this.checkZOrderTrigger(e19, t14, n11, r8), this.checkBoundsTrigger(e19, t14, n11, r8);
  };
  var Zi = { applyBypass: function(e19, t14, n11, r8) {
    var a8 = [];
    if ("*" === t14 || "**" === t14) {
      if (void 0 !== n11)
        for (var i9 = 0; i9 < this.properties.length; i9++) {
          var o11 = this.properties[i9].name, s10 = this.parse(o11, n11, true);
          s10 && a8.push(s10);
        }
    } else if (M6(t14)) {
      var l10 = this.parse(t14, n11, true);
      l10 && a8.push(l10);
    } else {
      if (!N6(t14))
        return false;
      var u9 = t14;
      r8 = n11;
      for (var c9 = Object.keys(u9), d10 = 0; d10 < c9.length; d10++) {
        var h9 = c9[d10], p9 = u9[h9];
        if (void 0 === p9 && (p9 = u9[X4(h9)]), void 0 !== p9) {
          var f10 = this.parse(h9, p9, true);
          f10 && a8.push(f10);
        }
      }
    }
    if (0 === a8.length)
      return false;
    for (var g8 = false, v11 = 0; v11 < e19.length; v11++) {
      for (var y9 = e19[v11], m11 = {}, b10 = void 0, x10 = 0; x10 < a8.length; x10++) {
        var w9 = a8[x10];
        if (r8) {
          var E8 = y9.pstyle(w9.name);
          b10 = m11[w9.name] = { prev: E8 };
        }
        g8 = this.applyParsedProperty(y9, Be(w9)) || g8, r8 && (b10.next = y9.pstyle(w9.name));
      }
      g8 && this.updateStyleHints(y9), r8 && this.updateTransitions(y9, m11, true);
    }
    return g8;
  }, overrideBypass: function(e19, t14, n11) {
    t14 = Y4(t14);
    for (var r8 = 0; r8 < e19.length; r8++) {
      var a8 = e19[r8], i9 = a8._private.style[t14], o11 = this.properties[t14].type, s10 = o11.color, l10 = o11.mutiple, u9 = i9 ? null != i9.pfValue ? i9.pfValue : i9.value : null;
      i9 && i9.bypass ? (i9.value = n11, null != i9.pfValue && (i9.pfValue = n11), i9.strValue = s10 ? "rgb(" + n11.join(",") + ")" : l10 ? n11.join(" ") : "" + n11, this.updateStyleHints(a8)) : this.applyBypass(a8, t14, n11), this.checkTriggers(a8, t14, u9, n11);
    }
  }, removeAllBypasses: function(e19, t14) {
    return this.removeBypasses(e19, this.propertyNames, t14);
  }, removeBypasses: function(e19, t14, n11) {
    for (var r8 = 0; r8 < e19.length; r8++) {
      for (var a8 = e19[r8], i9 = {}, o11 = 0; o11 < t14.length; o11++) {
        var s10 = t14[o11], l10 = this.properties[s10], u9 = a8.pstyle(l10.name);
        if (u9 && u9.bypass) {
          var c9 = this.parse(s10, "", true), d10 = i9[l10.name] = { prev: u9 };
          this.applyParsedProperty(a8, c9), d10.next = a8.pstyle(l10.name);
        }
      }
      this.updateStyleHints(a8), n11 && this.updateTransitions(a8, i9, true);
    }
  } };
  var $i = { getEmSizeInPixels: function() {
    var e19 = this.containerCss("font-size");
    return null != e19 ? parseFloat(e19) : 1;
  }, containerCss: function(e19) {
    var t14 = this._private.cy, n11 = t14.container(), r8 = t14.window();
    if (r8 && n11 && r8.getComputedStyle)
      return r8.getComputedStyle(n11).getPropertyValue(e19);
  } };
  var Qi = { getRenderedStyle: function(e19, t14) {
    return t14 ? this.getStylePropertyValue(e19, t14, true) : this.getRawStyle(e19, true);
  }, getRawStyle: function(e19, t14) {
    var n11 = this;
    if (e19 = e19[0]) {
      for (var r8 = {}, a8 = 0; a8 < n11.properties.length; a8++) {
        var i9 = n11.properties[a8], o11 = n11.getStylePropertyValue(e19, i9.name, t14);
        null != o11 && (r8[i9.name] = o11, r8[X4(i9.name)] = o11);
      }
      return r8;
    }
  }, getIndexedStyle: function(e19, t14, n11, r8) {
    var a8 = e19.pstyle(t14)[n11][r8];
    return null != a8 ? a8 : e19.cy().style().getDefaultProperty(t14)[n11][0];
  }, getStylePropertyValue: function(e19, t14, n11) {
    if (e19 = e19[0]) {
      var r8 = this.properties[t14];
      r8.alias && (r8 = r8.pointsTo);
      var a8 = r8.type, i9 = e19.pstyle(r8.name);
      if (i9) {
        var o11 = i9.value, s10 = i9.units, l10 = i9.strValue;
        if (n11 && a8.number && null != o11 && I6(o11)) {
          var u9 = e19.cy().zoom(), c9 = function(e20) {
            return e20 * u9;
          }, d10 = function(e20, t15) {
            return c9(e20) + t15;
          }, h9 = _5(o11);
          return (h9 ? s10.every(function(e20) {
            return null != e20;
          }) : null != s10) ? h9 ? o11.map(function(e20, t15) {
            return d10(e20, s10[t15]);
          }).join(" ") : d10(o11, s10) : h9 ? o11.map(function(e20) {
            return M6(e20) ? e20 : "" + c9(e20);
          }).join(" ") : "" + c9(o11);
        }
        if (null != l10)
          return l10;
      }
      return null;
    }
  }, getAnimationStartStyle: function(e19, t14) {
    for (var n11 = {}, r8 = 0; r8 < t14.length; r8++) {
      var a8 = t14[r8].name, i9 = e19.pstyle(a8);
      void 0 !== i9 && (i9 = N6(i9) ? this.parse(a8, i9.strValue) : this.parse(a8, i9)), i9 && (n11[a8] = i9);
    }
    return n11;
  }, getPropsList: function(e19) {
    var t14 = [], n11 = e19, r8 = this.properties;
    if (n11)
      for (var a8 = Object.keys(n11), i9 = 0; i9 < a8.length; i9++) {
        var o11 = a8[i9], s10 = n11[o11], l10 = r8[o11] || r8[Y4(o11)], u9 = this.parse(l10.name, s10);
        u9 && t14.push(u9);
      }
    return t14;
  }, getNonDefaultPropertiesHash: function(e19, t14, n11) {
    var r8, a8, i9, o11, s10, l10, u9 = n11.slice();
    for (s10 = 0; s10 < t14.length; s10++)
      if (r8 = t14[s10], null != (a8 = e19.pstyle(r8, false)))
        if (null != a8.pfValue)
          u9[0] = he(o11, u9[0]), u9[1] = pe(o11, u9[1]);
        else
          for (i9 = a8.strValue, l10 = 0; l10 < i9.length; l10++)
            o11 = i9.charCodeAt(l10), u9[0] = he(o11, u9[0]), u9[1] = pe(o11, u9[1]);
    return u9;
  } };
  Qi.getPropertiesHash = Qi.getNonDefaultPropertiesHash;
  var Ji = { appendFromJson: function(e19) {
    for (var t14 = this, n11 = 0; n11 < e19.length; n11++) {
      var r8 = e19[n11], a8 = r8.selector, i9 = r8.style || r8.css, o11 = Object.keys(i9);
      t14.selector(a8);
      for (var s10 = 0; s10 < o11.length; s10++) {
        var l10 = o11[s10], u9 = i9[l10];
        t14.css(l10, u9);
      }
    }
    return t14;
  }, fromJson: function(e19) {
    var t14 = this;
    return t14.resetToDefault(), t14.appendFromJson(e19), t14;
  }, json: function() {
    for (var e19 = [], t14 = this.defaultLength; t14 < this.length; t14++) {
      for (var n11 = this[t14], r8 = n11.selector, a8 = n11.properties, i9 = {}, o11 = 0; o11 < a8.length; o11++) {
        var s10 = a8[o11];
        i9[s10.name] = s10.strValue;
      }
      e19.push({ selector: r8 ? r8.toString() : "core", style: i9 });
    }
    return e19;
  } };
  var eo = { appendFromString: function(e19) {
    var t14, n11, r8, a8 = this, i9 = "" + e19;
    function o11() {
      i9 = i9.length > t14.length ? i9.substr(t14.length) : "";
    }
    function s10() {
      n11 = n11.length > r8.length ? n11.substr(r8.length) : "";
    }
    for (i9 = i9.replace(/[/][*](\s|.)+?[*][/]/g, ""); ; ) {
      if (i9.match(/^\s*$/))
        break;
      var l10 = i9.match(/^\s*((?:.|\s)+?)\s*\{((?:.|\s)+?)\}/);
      if (!l10) {
        Me("Halting stylesheet parsing: String stylesheet contains more to parse but no selector and block found in: " + i9);
        break;
      }
      t14 = l10[0];
      var u9 = l10[1];
      if ("core" !== u9) {
        if (new Kr(u9).invalid) {
          Me("Skipping parsing of block: Invalid selector found in string stylesheet: " + u9), o11();
          continue;
        }
      }
      var c9 = l10[2], d10 = false;
      n11 = c9;
      for (var h9 = []; ; ) {
        if (n11.match(/^\s*$/))
          break;
        var p9 = n11.match(/^\s*(.+?)\s*:\s*(.+?)(?:\s*;|\s*$)/);
        if (!p9) {
          Me("Skipping parsing of block: Invalid formatting of style property and value definitions found in:" + c9), d10 = true;
          break;
        }
        r8 = p9[0];
        var f10 = p9[1], g8 = p9[2];
        if (this.properties[f10])
          a8.parse(f10, g8) ? (h9.push({ name: f10, val: g8 }), s10()) : (Me("Skipping property: Invalid property definition in: " + r8), s10());
        else
          Me("Skipping property: Invalid property name in: " + r8), s10();
      }
      if (d10) {
        o11();
        break;
      }
      a8.selector(u9);
      for (var v11 = 0; v11 < h9.length; v11++) {
        var y9 = h9[v11];
        a8.css(y9.name, y9.val);
      }
      o11();
    }
    return a8;
  }, fromString: function(e19) {
    var t14 = this;
    return t14.resetToDefault(), t14.appendFromString(e19), t14;
  } };
  var to = {};
  !function() {
    var e19 = K4, t14 = U5, n11 = $5, r8 = function(e20) {
      return "^" + e20 + "\\s*\\(\\s*([\\w\\.]+)\\s*\\)$";
    }, a8 = function(r9) {
      var a9 = e19 + "|\\w+|" + t14 + "|" + n11 + "|\\#[0-9a-fA-F]{3}|\\#[0-9a-fA-F]{6}";
      return "^" + r9 + "\\s*\\(([\\w\\.]+)\\s*\\,\\s*(" + e19 + ")\\s*\\,\\s*(" + e19 + ")\\s*,\\s*(" + a9 + ")\\s*\\,\\s*(" + a9 + ")\\)$";
    }, i9 = [`^url\\s*\\(\\s*['"]?(.+?)['"]?\\s*\\)$`, "^(none)$", "^(.+)$"];
    to.types = { time: { number: true, min: 0, units: "s|ms", implicitUnits: "ms" }, percent: { number: true, min: 0, max: 100, units: "%", implicitUnits: "%" }, percentages: { number: true, min: 0, max: 100, units: "%", implicitUnits: "%", multiple: true }, zeroOneNumber: { number: true, min: 0, max: 1, unitless: true }, zeroOneNumbers: { number: true, min: 0, max: 1, unitless: true, multiple: true }, nOneOneNumber: { number: true, min: -1, max: 1, unitless: true }, nonNegativeInt: { number: true, min: 0, integer: true, unitless: true }, position: { enums: ["parent", "origin"] }, nodeSize: { number: true, min: 0, enums: ["label"] }, number: { number: true, unitless: true }, numbers: { number: true, unitless: true, multiple: true }, positiveNumber: { number: true, unitless: true, min: 0, strictMin: true }, size: { number: true, min: 0 }, bidirectionalSize: { number: true }, bidirectionalSizeMaybePercent: { number: true, allowPercent: true }, bidirectionalSizes: { number: true, multiple: true }, sizeMaybePercent: { number: true, min: 0, allowPercent: true }, axisDirection: { enums: ["horizontal", "leftward", "rightward", "vertical", "upward", "downward", "auto"] }, paddingRelativeTo: { enums: ["width", "height", "average", "min", "max"] }, bgWH: { number: true, min: 0, allowPercent: true, enums: ["auto"], multiple: true }, bgPos: { number: true, allowPercent: true, multiple: true }, bgRelativeTo: { enums: ["inner", "include-padding"], multiple: true }, bgRepeat: { enums: ["repeat", "repeat-x", "repeat-y", "no-repeat"], multiple: true }, bgFit: { enums: ["none", "contain", "cover"], multiple: true }, bgCrossOrigin: { enums: ["anonymous", "use-credentials", "null"], multiple: true }, bgClip: { enums: ["none", "node"], multiple: true }, bgContainment: { enums: ["inside", "over"], multiple: true }, color: { color: true }, colors: { color: true, multiple: true }, fill: { enums: ["solid", "linear-gradient", "radial-gradient"] }, bool: { enums: ["yes", "no"] }, bools: { enums: ["yes", "no"], multiple: true }, lineStyle: { enums: ["solid", "dotted", "dashed"] }, lineCap: { enums: ["butt", "round", "square"] }, borderStyle: { enums: ["solid", "dotted", "dashed", "double"] }, curveStyle: { enums: ["bezier", "unbundled-bezier", "haystack", "segments", "straight", "straight-triangle", "taxi"] }, fontFamily: { regex: '^([\\w- \\"]+(?:\\s*,\\s*[\\w- \\"]+)*)$' }, fontStyle: { enums: ["italic", "normal", "oblique"] }, fontWeight: { enums: ["normal", "bold", "bolder", "lighter", "100", "200", "300", "400", "500", "600", "800", "900", 100, 200, 300, 400, 500, 600, 700, 800, 900] }, textDecoration: { enums: ["none", "underline", "overline", "line-through"] }, textTransform: { enums: ["none", "uppercase", "lowercase"] }, textWrap: { enums: ["none", "wrap", "ellipsis"] }, textOverflowWrap: { enums: ["whitespace", "anywhere"] }, textBackgroundShape: { enums: ["rectangle", "roundrectangle", "round-rectangle"] }, nodeShape: { enums: ["rectangle", "roundrectangle", "round-rectangle", "cutrectangle", "cut-rectangle", "bottomroundrectangle", "bottom-round-rectangle", "barrel", "ellipse", "triangle", "round-triangle", "square", "pentagon", "round-pentagon", "hexagon", "round-hexagon", "concavehexagon", "concave-hexagon", "heptagon", "round-heptagon", "octagon", "round-octagon", "tag", "round-tag", "star", "diamond", "round-diamond", "vee", "rhomboid", "right-rhomboid", "polygon"] }, overlayShape: { enums: ["roundrectangle", "round-rectangle", "ellipse"] }, compoundIncludeLabels: { enums: ["include", "exclude"] }, arrowShape: { enums: ["tee", "triangle", "triangle-tee", "circle-triangle", "triangle-cross", "triangle-backcurve", "vee", "square", "circle", "diamond", "chevron", "none"] }, arrowFill: { enums: ["filled", "hollow"] }, display: { enums: ["element", "none"] }, visibility: { enums: ["hidden", "visible"] }, zCompoundDepth: { enums: ["bottom", "orphan", "auto", "top"] }, zIndexCompare: { enums: ["auto", "manual"] }, valign: { enums: ["top", "center", "bottom"] }, halign: { enums: ["left", "center", "right"] }, justification: { enums: ["left", "center", "right", "auto"] }, text: { string: true }, data: { mapping: true, regex: r8("data") }, layoutData: { mapping: true, regex: r8("layoutData") }, scratch: { mapping: true, regex: r8("scratch") }, mapData: { mapping: true, regex: a8("mapData") }, mapLayoutData: { mapping: true, regex: a8("mapLayoutData") }, mapScratch: { mapping: true, regex: a8("mapScratch") }, fn: { mapping: true, fn: true }, url: { regexes: i9, singleRegexMatchValue: true }, urls: { regexes: i9, singleRegexMatchValue: true, multiple: true }, propList: { propList: true }, angle: { number: true, units: "deg|rad", implicitUnits: "rad" }, textRotation: { number: true, units: "deg|rad", implicitUnits: "rad", enums: ["none", "autorotate"] }, polygonPointList: { number: true, multiple: true, evenMultiple: true, min: -1, max: 1, unitless: true }, edgeDistances: { enums: ["intersection", "node-position"] }, edgeEndpoint: { number: true, multiple: true, units: "%|px|em|deg|rad", implicitUnits: "px", enums: ["inside-to-node", "outside-to-node", "outside-to-node-or-label", "outside-to-line", "outside-to-line-or-label"], singleEnum: true, validate: function(e20, t15) {
      switch (e20.length) {
        case 2:
          return "deg" !== t15[0] && "rad" !== t15[0] && "deg" !== t15[1] && "rad" !== t15[1];
        case 1:
          return M6(e20[0]) || "deg" === t15[0] || "rad" === t15[0];
        default:
          return false;
      }
    } }, easing: { regexes: ["^(spring)\\s*\\(\\s*(" + e19 + ")\\s*,\\s*(" + e19 + ")\\s*\\)$", "^(cubic-bezier)\\s*\\(\\s*(" + e19 + ")\\s*,\\s*(" + e19 + ")\\s*,\\s*(" + e19 + ")\\s*,\\s*(" + e19 + ")\\s*\\)$"], enums: ["linear", "ease", "ease-in", "ease-out", "ease-in-out", "ease-in-sine", "ease-out-sine", "ease-in-out-sine", "ease-in-quad", "ease-out-quad", "ease-in-out-quad", "ease-in-cubic", "ease-out-cubic", "ease-in-out-cubic", "ease-in-quart", "ease-out-quart", "ease-in-out-quart", "ease-in-quint", "ease-out-quint", "ease-in-out-quint", "ease-in-expo", "ease-out-expo", "ease-in-out-expo", "ease-in-circ", "ease-out-circ", "ease-in-out-circ"] }, gradientDirection: { enums: ["to-bottom", "to-top", "to-left", "to-right", "to-bottom-right", "to-bottom-left", "to-top-right", "to-top-left", "to-right-bottom", "to-left-bottom", "to-right-top", "to-left-top"] }, boundsExpansion: { number: true, multiple: true, min: 0, validate: function(e20) {
      var t15 = e20.length;
      return 1 === t15 || 2 === t15 || 4 === t15;
    } } };
    var o11 = { zeroNonZero: function(e20, t15) {
      return (null == e20 || null == t15) && e20 !== t15 || (0 == e20 && 0 != t15 || 0 != e20 && 0 == t15);
    }, any: function(e20, t15) {
      return e20 != t15;
    }, emptyNonEmpty: function(e20, t15) {
      var n12 = F5(e20), r9 = F5(t15);
      return n12 && !r9 || !n12 && r9;
    } }, s10 = to.types, l10 = [{ name: "label", type: s10.text, triggersBounds: o11.any, triggersZOrder: o11.emptyNonEmpty }, { name: "text-rotation", type: s10.textRotation, triggersBounds: o11.any }, { name: "text-margin-x", type: s10.bidirectionalSize, triggersBounds: o11.any }, { name: "text-margin-y", type: s10.bidirectionalSize, triggersBounds: o11.any }], u9 = [{ name: "source-label", type: s10.text, triggersBounds: o11.any }, { name: "source-text-rotation", type: s10.textRotation, triggersBounds: o11.any }, { name: "source-text-margin-x", type: s10.bidirectionalSize, triggersBounds: o11.any }, { name: "source-text-margin-y", type: s10.bidirectionalSize, triggersBounds: o11.any }, { name: "source-text-offset", type: s10.size, triggersBounds: o11.any }], c9 = [{ name: "target-label", type: s10.text, triggersBounds: o11.any }, { name: "target-text-rotation", type: s10.textRotation, triggersBounds: o11.any }, { name: "target-text-margin-x", type: s10.bidirectionalSize, triggersBounds: o11.any }, { name: "target-text-margin-y", type: s10.bidirectionalSize, triggersBounds: o11.any }, { name: "target-text-offset", type: s10.size, triggersBounds: o11.any }], d10 = [{ name: "font-family", type: s10.fontFamily, triggersBounds: o11.any }, { name: "font-style", type: s10.fontStyle, triggersBounds: o11.any }, { name: "font-weight", type: s10.fontWeight, triggersBounds: o11.any }, { name: "font-size", type: s10.size, triggersBounds: o11.any }, { name: "text-transform", type: s10.textTransform, triggersBounds: o11.any }, { name: "text-wrap", type: s10.textWrap, triggersBounds: o11.any }, { name: "text-overflow-wrap", type: s10.textOverflowWrap, triggersBounds: o11.any }, { name: "text-max-width", type: s10.size, triggersBounds: o11.any }, { name: "text-outline-width", type: s10.size, triggersBounds: o11.any }, { name: "line-height", type: s10.positiveNumber, triggersBounds: o11.any }], h9 = [{ name: "text-valign", type: s10.valign, triggersBounds: o11.any }, { name: "text-halign", type: s10.halign, triggersBounds: o11.any }, { name: "color", type: s10.color }, { name: "text-outline-color", type: s10.color }, { name: "text-outline-opacity", type: s10.zeroOneNumber }, { name: "text-background-color", type: s10.color }, { name: "text-background-opacity", type: s10.zeroOneNumber }, { name: "text-background-padding", type: s10.size, triggersBounds: o11.any }, { name: "text-border-opacity", type: s10.zeroOneNumber }, { name: "text-border-color", type: s10.color }, { name: "text-border-width", type: s10.size, triggersBounds: o11.any }, { name: "text-border-style", type: s10.borderStyle, triggersBounds: o11.any }, { name: "text-background-shape", type: s10.textBackgroundShape, triggersBounds: o11.any }, { name: "text-justification", type: s10.justification }], p9 = [{ name: "events", type: s10.bool }, { name: "text-events", type: s10.bool }], f10 = [{ name: "display", type: s10.display, triggersZOrder: o11.any, triggersBounds: o11.any, triggersBoundsOfParallelBeziers: true }, { name: "visibility", type: s10.visibility, triggersZOrder: o11.any }, { name: "opacity", type: s10.zeroOneNumber, triggersZOrder: o11.zeroNonZero }, { name: "text-opacity", type: s10.zeroOneNumber }, { name: "min-zoomed-font-size", type: s10.size }, { name: "z-compound-depth", type: s10.zCompoundDepth, triggersZOrder: o11.any }, { name: "z-index-compare", type: s10.zIndexCompare, triggersZOrder: o11.any }, { name: "z-index", type: s10.nonNegativeInt, triggersZOrder: o11.any }], g8 = [{ name: "overlay-padding", type: s10.size, triggersBounds: o11.any }, { name: "overlay-color", type: s10.color }, { name: "overlay-opacity", type: s10.zeroOneNumber, triggersBounds: o11.zeroNonZero }, { name: "overlay-shape", type: s10.overlayShape, triggersBounds: o11.any }], v11 = [{ name: "underlay-padding", type: s10.size, triggersBounds: o11.any }, { name: "underlay-color", type: s10.color }, { name: "underlay-opacity", type: s10.zeroOneNumber, triggersBounds: o11.zeroNonZero }, { name: "underlay-shape", type: s10.overlayShape, triggersBounds: o11.any }], y9 = [{ name: "transition-property", type: s10.propList }, { name: "transition-duration", type: s10.time }, { name: "transition-delay", type: s10.time }, { name: "transition-timing-function", type: s10.easing }], m11 = function(e20, t15) {
      return "label" === t15.value ? -e20.poolIndex() : t15.pfValue;
    }, b10 = [{ name: "height", type: s10.nodeSize, triggersBounds: o11.any, hashOverride: m11 }, { name: "width", type: s10.nodeSize, triggersBounds: o11.any, hashOverride: m11 }, { name: "shape", type: s10.nodeShape, triggersBounds: o11.any }, { name: "shape-polygon-points", type: s10.polygonPointList, triggersBounds: o11.any }, { name: "background-color", type: s10.color }, { name: "background-fill", type: s10.fill }, { name: "background-opacity", type: s10.zeroOneNumber }, { name: "background-blacken", type: s10.nOneOneNumber }, { name: "background-gradient-stop-colors", type: s10.colors }, { name: "background-gradient-stop-positions", type: s10.percentages }, { name: "background-gradient-direction", type: s10.gradientDirection }, { name: "padding", type: s10.sizeMaybePercent, triggersBounds: o11.any }, { name: "padding-relative-to", type: s10.paddingRelativeTo, triggersBounds: o11.any }, { name: "bounds-expansion", type: s10.boundsExpansion, triggersBounds: o11.any }], x10 = [{ name: "border-color", type: s10.color }, { name: "border-opacity", type: s10.zeroOneNumber }, { name: "border-width", type: s10.size, triggersBounds: o11.any }, { name: "border-style", type: s10.borderStyle }], w9 = [{ name: "background-image", type: s10.urls }, { name: "background-image-crossorigin", type: s10.bgCrossOrigin }, { name: "background-image-opacity", type: s10.zeroOneNumbers }, { name: "background-image-containment", type: s10.bgContainment }, { name: "background-image-smoothing", type: s10.bools }, { name: "background-position-x", type: s10.bgPos }, { name: "background-position-y", type: s10.bgPos }, { name: "background-width-relative-to", type: s10.bgRelativeTo }, { name: "background-height-relative-to", type: s10.bgRelativeTo }, { name: "background-repeat", type: s10.bgRepeat }, { name: "background-fit", type: s10.bgFit }, { name: "background-clip", type: s10.bgClip }, { name: "background-width", type: s10.bgWH }, { name: "background-height", type: s10.bgWH }, { name: "background-offset-x", type: s10.bgPos }, { name: "background-offset-y", type: s10.bgPos }], E8 = [{ name: "position", type: s10.position, triggersBounds: o11.any }, { name: "compound-sizing-wrt-labels", type: s10.compoundIncludeLabels, triggersBounds: o11.any }, { name: "min-width", type: s10.size, triggersBounds: o11.any }, { name: "min-width-bias-left", type: s10.sizeMaybePercent, triggersBounds: o11.any }, { name: "min-width-bias-right", type: s10.sizeMaybePercent, triggersBounds: o11.any }, { name: "min-height", type: s10.size, triggersBounds: o11.any }, { name: "min-height-bias-top", type: s10.sizeMaybePercent, triggersBounds: o11.any }, { name: "min-height-bias-bottom", type: s10.sizeMaybePercent, triggersBounds: o11.any }], k9 = [{ name: "line-style", type: s10.lineStyle }, { name: "line-color", type: s10.color }, { name: "line-fill", type: s10.fill }, { name: "line-cap", type: s10.lineCap }, { name: "line-opacity", type: s10.zeroOneNumber }, { name: "line-dash-pattern", type: s10.numbers }, { name: "line-dash-offset", type: s10.number }, { name: "line-gradient-stop-colors", type: s10.colors }, { name: "line-gradient-stop-positions", type: s10.percentages }, { name: "curve-style", type: s10.curveStyle, triggersBounds: o11.any, triggersBoundsOfParallelBeziers: true }, { name: "haystack-radius", type: s10.zeroOneNumber, triggersBounds: o11.any }, { name: "source-endpoint", type: s10.edgeEndpoint, triggersBounds: o11.any }, { name: "target-endpoint", type: s10.edgeEndpoint, triggersBounds: o11.any }, { name: "control-point-step-size", type: s10.size, triggersBounds: o11.any }, { name: "control-point-distances", type: s10.bidirectionalSizes, triggersBounds: o11.any }, { name: "control-point-weights", type: s10.numbers, triggersBounds: o11.any }, { name: "segment-distances", type: s10.bidirectionalSizes, triggersBounds: o11.any }, { name: "segment-weights", type: s10.numbers, triggersBounds: o11.any }, { name: "taxi-turn", type: s10.bidirectionalSizeMaybePercent, triggersBounds: o11.any }, { name: "taxi-turn-min-distance", type: s10.size, triggersBounds: o11.any }, { name: "taxi-direction", type: s10.axisDirection, triggersBounds: o11.any }, { name: "edge-distances", type: s10.edgeDistances, triggersBounds: o11.any }, { name: "arrow-scale", type: s10.positiveNumber, triggersBounds: o11.any }, { name: "loop-direction", type: s10.angle, triggersBounds: o11.any }, { name: "loop-sweep", type: s10.angle, triggersBounds: o11.any }, { name: "source-distance-from-node", type: s10.size, triggersBounds: o11.any }, { name: "target-distance-from-node", type: s10.size, triggersBounds: o11.any }], C8 = [{ name: "ghost", type: s10.bool, triggersBounds: o11.any }, { name: "ghost-offset-x", type: s10.bidirectionalSize, triggersBounds: o11.any }, { name: "ghost-offset-y", type: s10.bidirectionalSize, triggersBounds: o11.any }, { name: "ghost-opacity", type: s10.zeroOneNumber }], S7 = [{ name: "selection-box-color", type: s10.color }, { name: "selection-box-opacity", type: s10.zeroOneNumber }, { name: "selection-box-border-color", type: s10.color }, { name: "selection-box-border-width", type: s10.size }, { name: "active-bg-color", type: s10.color }, { name: "active-bg-opacity", type: s10.zeroOneNumber }, { name: "active-bg-size", type: s10.size }, { name: "outside-texture-bg-color", type: s10.color }, { name: "outside-texture-bg-opacity", type: s10.zeroOneNumber }], D7 = [];
    to.pieBackgroundN = 16, D7.push({ name: "pie-size", type: s10.sizeMaybePercent });
    for (var P9 = 1; P9 <= to.pieBackgroundN; P9++)
      D7.push({ name: "pie-" + P9 + "-background-color", type: s10.color }), D7.push({ name: "pie-" + P9 + "-background-size", type: s10.percent }), D7.push({ name: "pie-" + P9 + "-background-opacity", type: s10.zeroOneNumber });
    var T8 = [], B8 = to.arrowPrefixes = ["source", "mid-source", "target", "mid-target"];
    [{ name: "arrow-shape", type: s10.arrowShape, triggersBounds: o11.any }, { name: "arrow-color", type: s10.color }, { name: "arrow-fill", type: s10.arrowFill }].forEach(function(e20) {
      B8.forEach(function(t15) {
        var n12 = t15 + "-" + e20.name, r9 = e20.type, a9 = e20.triggersBounds;
        T8.push({ name: n12, type: r9, triggersBounds: a9 });
      });
    }, {});
    var _6 = to.properties = [].concat(p9, y9, f10, g8, v11, C8, h9, d10, l10, u9, c9, b10, x10, w9, D7, E8, k9, T8, S7), N7 = to.propertyGroups = { behavior: p9, transition: y9, visibility: f10, overlay: g8, underlay: v11, ghost: C8, commonLabel: h9, labelDimensions: d10, mainLabel: l10, sourceLabel: u9, targetLabel: c9, nodeBody: b10, nodeBorder: x10, backgroundImage: w9, pie: D7, compound: E8, edgeLine: k9, edgeArrow: T8, core: S7 }, I7 = to.propertyGroupNames = {};
    (to.propertyGroupKeys = Object.keys(N7)).forEach(function(e20) {
      I7[e20] = N7[e20].map(function(e21) {
        return e21.name;
      }), N7[e20].forEach(function(t15) {
        return t15.groupKey = e20;
      });
    });
    var z7 = to.aliases = [{ name: "content", pointsTo: "label" }, { name: "control-point-distance", pointsTo: "control-point-distances" }, { name: "control-point-weight", pointsTo: "control-point-weights" }, { name: "edge-text-rotation", pointsTo: "text-rotation" }, { name: "padding-left", pointsTo: "padding" }, { name: "padding-right", pointsTo: "padding" }, { name: "padding-top", pointsTo: "padding" }, { name: "padding-bottom", pointsTo: "padding" }];
    to.propertyNames = _6.map(function(e20) {
      return e20.name;
    });
    for (var L9 = 0; L9 < _6.length; L9++) {
      var A9 = _6[L9];
      _6[A9.name] = A9;
    }
    for (var O8 = 0; O8 < z7.length; O8++) {
      var R7 = z7[O8], V6 = _6[R7.pointsTo], q7 = { name: R7.name, alias: true, pointsTo: V6 };
      _6.push(q7), _6[R7.name] = q7;
    }
  }(), to.getDefaultProperty = function(e19) {
    return this.getDefaultProperties()[e19];
  }, to.getDefaultProperties = function() {
    var e19 = this._private;
    if (null != e19.defaultProperties)
      return e19.defaultProperties;
    for (var t14 = J4({ "selection-box-color": "#ddd", "selection-box-opacity": 0.65, "selection-box-border-color": "#aaa", "selection-box-border-width": 1, "active-bg-color": "black", "active-bg-opacity": 0.15, "active-bg-size": 30, "outside-texture-bg-color": "#000", "outside-texture-bg-opacity": 0.125, events: "yes", "text-events": "no", "text-valign": "top", "text-halign": "center", "text-justification": "auto", "line-height": 1, color: "#000", "text-outline-color": "#000", "text-outline-width": 0, "text-outline-opacity": 1, "text-opacity": 1, "text-decoration": "none", "text-transform": "none", "text-wrap": "none", "text-overflow-wrap": "whitespace", "text-max-width": 9999, "text-background-color": "#000", "text-background-opacity": 0, "text-background-shape": "rectangle", "text-background-padding": 0, "text-border-opacity": 0, "text-border-width": 0, "text-border-style": "solid", "text-border-color": "#000", "font-family": "Helvetica Neue, Helvetica, sans-serif", "font-style": "normal", "font-weight": "normal", "font-size": 16, "min-zoomed-font-size": 0, "text-rotation": "none", "source-text-rotation": "none", "target-text-rotation": "none", visibility: "visible", display: "element", opacity: 1, "z-compound-depth": "auto", "z-index-compare": "auto", "z-index": 0, label: "", "text-margin-x": 0, "text-margin-y": 0, "source-label": "", "source-text-offset": 0, "source-text-margin-x": 0, "source-text-margin-y": 0, "target-label": "", "target-text-offset": 0, "target-text-margin-x": 0, "target-text-margin-y": 0, "overlay-opacity": 0, "overlay-color": "#000", "overlay-padding": 10, "overlay-shape": "round-rectangle", "underlay-opacity": 0, "underlay-color": "#000", "underlay-padding": 10, "underlay-shape": "round-rectangle", "transition-property": "none", "transition-duration": 0, "transition-delay": 0, "transition-timing-function": "linear", "background-blacken": 0, "background-color": "#999", "background-fill": "solid", "background-opacity": 1, "background-image": "none", "background-image-crossorigin": "anonymous", "background-image-opacity": 1, "background-image-containment": "inside", "background-image-smoothing": "yes", "background-position-x": "50%", "background-position-y": "50%", "background-offset-x": 0, "background-offset-y": 0, "background-width-relative-to": "include-padding", "background-height-relative-to": "include-padding", "background-repeat": "no-repeat", "background-fit": "none", "background-clip": "node", "background-width": "auto", "background-height": "auto", "border-color": "#000", "border-opacity": 1, "border-width": 0, "border-style": "solid", height: 30, width: 30, shape: "ellipse", "shape-polygon-points": "-1, -1,   1, -1,   1, 1,   -1, 1", "bounds-expansion": 0, "background-gradient-direction": "to-bottom", "background-gradient-stop-colors": "#999", "background-gradient-stop-positions": "0%", ghost: "no", "ghost-offset-y": 0, "ghost-offset-x": 0, "ghost-opacity": 0, padding: 0, "padding-relative-to": "width", position: "origin", "compound-sizing-wrt-labels": "include", "min-width": 0, "min-width-bias-left": 0, "min-width-bias-right": 0, "min-height": 0, "min-height-bias-top": 0, "min-height-bias-bottom": 0 }, { "pie-size": "100%" }, [{ name: "pie-{{i}}-background-color", value: "black" }, { name: "pie-{{i}}-background-size", value: "0%" }, { name: "pie-{{i}}-background-opacity", value: 1 }].reduce(function(e20, t15) {
      for (var n12 = 1; n12 <= to.pieBackgroundN; n12++) {
        var r9 = t15.name.replace("{{i}}", n12), a9 = t15.value;
        e20[r9] = a9;
      }
      return e20;
    }, {}), { "line-style": "solid", "line-color": "#999", "line-fill": "solid", "line-cap": "butt", "line-opacity": 1, "line-gradient-stop-colors": "#999", "line-gradient-stop-positions": "0%", "control-point-step-size": 40, "control-point-weights": 0.5, "segment-weights": 0.5, "segment-distances": 20, "taxi-turn": "50%", "taxi-turn-min-distance": 10, "taxi-direction": "auto", "edge-distances": "intersection", "curve-style": "haystack", "haystack-radius": 0, "arrow-scale": 1, "loop-direction": "-45deg", "loop-sweep": "-90deg", "source-distance-from-node": 0, "target-distance-from-node": 0, "source-endpoint": "outside-to-node", "target-endpoint": "outside-to-node", "line-dash-pattern": [6, 3], "line-dash-offset": 0 }, [{ name: "arrow-shape", value: "none" }, { name: "arrow-color", value: "#999" }, { name: "arrow-fill", value: "filled" }].reduce(function(e20, t15) {
      return to.arrowPrefixes.forEach(function(n12) {
        var r9 = n12 + "-" + t15.name, a9 = t15.value;
        e20[r9] = a9;
      }), e20;
    }, {})), n11 = {}, r8 = 0; r8 < this.properties.length; r8++) {
      var a8 = this.properties[r8];
      if (!a8.pointsTo) {
        var i9 = a8.name, o11 = t14[i9], s10 = this.parse(i9, o11);
        n11[i9] = s10;
      }
    }
    return e19.defaultProperties = n11, e19.defaultProperties;
  }, to.addDefaultStylesheet = function() {
    this.selector(":parent").css({ shape: "rectangle", padding: 10, "background-color": "#eee", "border-color": "#ccc", "border-width": 1 }).selector("edge").css({ width: 3 }).selector(":loop").css({ "curve-style": "bezier" }).selector("edge:compound").css({ "curve-style": "bezier", "source-endpoint": "outside-to-line", "target-endpoint": "outside-to-line" }).selector(":selected").css({ "background-color": "#0169D9", "line-color": "#0169D9", "source-arrow-color": "#0169D9", "target-arrow-color": "#0169D9", "mid-source-arrow-color": "#0169D9", "mid-target-arrow-color": "#0169D9" }).selector(":parent:selected").css({ "background-color": "#CCE1F9", "border-color": "#aec8e5" }).selector(":active").css({ "overlay-color": "black", "overlay-padding": 10, "overlay-opacity": 0.25 }), this.defaultLength = this.length;
  };
  var no = { parse: function(e19, t14, n11, r8) {
    var a8 = this;
    if (B5(t14))
      return a8.parseImplWarn(e19, t14, n11, r8);
    var i9, o11 = ye(e19, "" + t14, n11 ? "t" : "f", "mapping" === r8 || true === r8 || false === r8 || null == r8 ? "dontcare" : r8), s10 = a8.propCache = a8.propCache || [];
    return (i9 = s10[o11]) || (i9 = s10[o11] = a8.parseImplWarn(e19, t14, n11, r8)), (n11 || "mapping" === r8) && (i9 = Be(i9)) && (i9.value = Be(i9.value)), i9;
  }, parseImplWarn: function(e19, t14, n11, r8) {
    var a8 = this.parseImpl(e19, t14, n11, r8);
    return a8 || null == t14 || Me("The style property `".concat(e19, ": ").concat(t14, "` is invalid")), !a8 || "width" !== a8.name && "height" !== a8.name || "label" !== t14 || Me("The style value of `label` is deprecated for `" + a8.name + "`"), a8;
  } };
  no.parseImpl = function(e19, t14, n11, r8) {
    var a8 = this;
    e19 = Y4(e19);
    var i9 = a8.properties[e19], o11 = t14, s10 = a8.types;
    if (!i9)
      return null;
    if (void 0 === t14)
      return null;
    i9.alias && (i9 = i9.pointsTo, e19 = i9.name);
    var l10 = M6(t14);
    l10 && (t14 = t14.trim());
    var u9, c9, d10 = i9.type;
    if (!d10)
      return null;
    if (n11 && ("" === t14 || null === t14))
      return { name: e19, value: t14, bypass: true, deleteBypass: true };
    if (B5(t14))
      return { name: e19, value: t14, strValue: "fn", mapped: s10.fn, bypass: n11 };
    if (!l10 || r8 || t14.length < 7 || "a" !== t14[1])
      ;
    else {
      if (t14.length >= 7 && "d" === t14[0] && (u9 = new RegExp(s10.data.regex).exec(t14))) {
        if (n11)
          return false;
        var h9 = s10.data;
        return { name: e19, value: u9, strValue: "" + t14, mapped: h9, field: u9[1], bypass: n11 };
      }
      if (t14.length >= 10 && "m" === t14[0] && (c9 = new RegExp(s10.mapData.regex).exec(t14))) {
        if (n11)
          return false;
        if (d10.multiple)
          return false;
        var p9 = s10.mapData;
        if (!d10.color && !d10.number)
          return false;
        var f10 = this.parse(e19, c9[4]);
        if (!f10 || f10.mapped)
          return false;
        var g8 = this.parse(e19, c9[5]);
        if (!g8 || g8.mapped)
          return false;
        if (f10.pfValue === g8.pfValue || f10.strValue === g8.strValue)
          return Me("`" + e19 + ": " + t14 + "` is not a valid mapper because the output range is zero; converting to `" + e19 + ": " + f10.strValue + "`"), this.parse(e19, f10.strValue);
        if (d10.color) {
          var v11 = f10.value, y9 = g8.value;
          if (!(v11[0] !== y9[0] || v11[1] !== y9[1] || v11[2] !== y9[2] || v11[3] !== y9[3] && (null != v11[3] && 1 !== v11[3] || null != y9[3] && 1 !== y9[3])))
            return false;
        }
        return { name: e19, value: c9, strValue: "" + t14, mapped: p9, field: c9[1], fieldMin: parseFloat(c9[2]), fieldMax: parseFloat(c9[3]), valueMin: f10.value, valueMax: g8.value, bypass: n11 };
      }
    }
    if (d10.multiple && "multiple" !== r8) {
      var m11;
      if (m11 = l10 ? t14.split(/\s+/) : _5(t14) ? t14 : [t14], d10.evenMultiple && m11.length % 2 != 0)
        return null;
      for (var b10 = [], x10 = [], w9 = [], E8 = "", k9 = false, C8 = 0; C8 < m11.length; C8++) {
        var S7 = a8.parse(e19, m11[C8], n11, "multiple");
        k9 = k9 || M6(S7.value), b10.push(S7.value), w9.push(null != S7.pfValue ? S7.pfValue : S7.value), x10.push(S7.units), E8 += (C8 > 0 ? " " : "") + S7.strValue;
      }
      return d10.validate && !d10.validate(b10, x10) ? null : d10.singleEnum && k9 ? 1 === b10.length && M6(b10[0]) ? { name: e19, value: b10[0], strValue: b10[0], bypass: n11 } : null : { name: e19, value: b10, pfValue: w9, strValue: E8, bypass: n11, units: x10 };
    }
    var D7, P9, T8 = function() {
      for (var r9 = 0; r9 < d10.enums.length; r9++) {
        if (d10.enums[r9] === t14)
          return { name: e19, value: t14, strValue: "" + t14, bypass: n11 };
      }
      return null;
    };
    if (d10.number) {
      var N7, z7 = "px";
      if (d10.units && (N7 = d10.units), d10.implicitUnits && (z7 = d10.implicitUnits), !d10.unitless)
        if (l10) {
          var L9 = "px|em" + (d10.allowPercent ? "|\\%" : "");
          N7 && (L9 = N7);
          var A9 = t14.match("^(" + K4 + ")(" + L9 + ")?$");
          A9 && (t14 = A9[1], N7 = A9[2] || z7);
        } else
          N7 && !d10.implicitUnits || (N7 = z7);
      if (t14 = parseFloat(t14), isNaN(t14) && void 0 === d10.enums)
        return null;
      if (isNaN(t14) && void 0 !== d10.enums)
        return t14 = o11, T8();
      if (d10.integer && (!I6(P9 = t14) || Math.floor(P9) !== P9))
        return null;
      if (void 0 !== d10.min && (t14 < d10.min || d10.strictMin && t14 === d10.min) || void 0 !== d10.max && (t14 > d10.max || d10.strictMax && t14 === d10.max))
        return null;
      var O8 = { name: e19, value: t14, strValue: "" + t14 + (N7 || ""), units: N7, bypass: n11 };
      return d10.unitless || "px" !== N7 && "em" !== N7 ? O8.pfValue = t14 : O8.pfValue = "px" !== N7 && N7 ? this.getEmSizeInPixels() * t14 : t14, "ms" !== N7 && "s" !== N7 || (O8.pfValue = "ms" === N7 ? t14 : 1e3 * t14), "deg" !== N7 && "rad" !== N7 || (O8.pfValue = "rad" === N7 ? t14 : (D7 = t14, Math.PI * D7 / 180)), "%" === N7 && (O8.pfValue = t14 / 100), O8;
    }
    if (d10.propList) {
      var R7 = [], V6 = "" + t14;
      if ("none" === V6)
        ;
      else {
        for (var F7 = V6.split(/\s*,\s*|\s+/), q7 = 0; q7 < F7.length; q7++) {
          var j8 = F7[q7].trim();
          a8.properties[j8] ? R7.push(j8) : Me("`" + j8 + "` is not a valid property name");
        }
        if (0 === R7.length)
          return null;
      }
      return { name: e19, value: R7, strValue: 0 === R7.length ? "none" : R7.join(" "), bypass: n11 };
    }
    if (d10.color) {
      var X5 = ee(t14);
      return X5 ? { name: e19, value: X5, pfValue: X5, strValue: "rgb(" + X5[0] + "," + X5[1] + "," + X5[2] + ")", bypass: n11 } : null;
    }
    if (d10.regex || d10.regexes) {
      if (d10.enums) {
        var W7 = T8();
        if (W7)
          return W7;
      }
      for (var H8 = d10.regexes ? d10.regexes : [d10.regex], G5 = 0; G5 < H8.length; G5++) {
        var U6 = new RegExp(H8[G5]).exec(t14);
        if (U6)
          return { name: e19, value: d10.singleRegexMatchValue ? U6[1] : U6, strValue: "" + t14, bypass: n11 };
      }
      return null;
    }
    return d10.string ? { name: e19, value: "" + t14, strValue: "" + t14, bypass: n11 } : d10.enums ? T8() : null;
  };
  var ro = function e12(t14) {
    if (!(this instanceof e12))
      return new e12(t14);
    R4(t14) ? (this._private = { cy: t14, coreStyle: {} }, this.length = 0, this.resetToDefault()) : Pe("A style must have a core reference");
  };
  var ao = ro.prototype;
  ao.instanceString = function() {
    return "style";
  }, ao.clear = function() {
    for (var e19 = this._private, t14 = e19.cy.elements(), n11 = 0; n11 < this.length; n11++)
      this[n11] = void 0;
    return this.length = 0, e19.contextStyles = {}, e19.propDiffs = {}, this.cleanElements(t14, true), t14.forEach(function(e20) {
      var t15 = e20[0]._private;
      t15.styleDirty = true, t15.appliedInitStyle = false;
    }), this;
  }, ao.resetToDefault = function() {
    return this.clear(), this.addDefaultStylesheet(), this;
  }, ao.core = function(e19) {
    return this._private.coreStyle[e19] || this.getDefaultProperty(e19);
  }, ao.selector = function(e19) {
    var t14 = "core" === e19 ? null : new Kr(e19), n11 = this.length++;
    return this[n11] = { selector: t14, properties: [], mappedProperties: [], index: n11 }, this;
  }, ao.css = function() {
    var e19 = arguments;
    if (1 === e19.length)
      for (var t14 = e19[0], n11 = 0; n11 < this.properties.length; n11++) {
        var r8 = this.properties[n11], a8 = t14[r8.name];
        void 0 === a8 && (a8 = t14[X4(r8.name)]), void 0 !== a8 && this.cssRule(r8.name, a8);
      }
    else
      2 === e19.length && this.cssRule(e19[0], e19[1]);
    return this;
  }, ao.style = ao.css, ao.cssRule = function(e19, t14) {
    var n11 = this.parse(e19, t14);
    if (n11) {
      var r8 = this.length - 1;
      this[r8].properties.push(n11), this[r8].properties[n11.name] = n11, n11.name.match(/pie-(\d+)-background-size/) && n11.value && (this._private.hasPie = true), n11.mapped && this[r8].mappedProperties.push(n11), !this[r8].selector && (this._private.coreStyle[n11.name] = n11);
    }
    return this;
  }, ao.append = function(e19) {
    return V4(e19) ? e19.appendToStyle(this) : _5(e19) ? this.appendFromJson(e19) : M6(e19) && this.appendFromString(e19), this;
  }, ro.fromJson = function(e19, t14) {
    var n11 = new ro(e19);
    return n11.fromJson(t14), n11;
  }, ro.fromString = function(e19, t14) {
    return new ro(e19).fromString(t14);
  }, [Gi, Zi, $i, Qi, Ji, eo, to, no].forEach(function(e19) {
    J4(ao, e19);
  }), ro.types = ao.types, ro.properties = ao.properties, ro.propertyGroups = ao.propertyGroups, ro.propertyGroupNames = ao.propertyGroupNames, ro.propertyGroupKeys = ao.propertyGroupKeys;
  var io = { style: function(e19) {
    e19 && this.setStyle(e19).update();
    return this._private.style;
  }, setStyle: function(e19) {
    var t14 = this._private;
    return V4(e19) ? t14.style = e19.generateStyle(this) : _5(e19) ? t14.style = ro.fromJson(this, e19) : M6(e19) ? t14.style = ro.fromString(this, e19) : t14.style = ro(this), t14.style;
  }, updateStyle: function() {
    this.mutableElements().updateStyle();
  } };
  var oo = { autolock: function(e19) {
    return void 0 === e19 ? this._private.autolock : (this._private.autolock = !!e19, this);
  }, autoungrabify: function(e19) {
    return void 0 === e19 ? this._private.autoungrabify : (this._private.autoungrabify = !!e19, this);
  }, autounselectify: function(e19) {
    return void 0 === e19 ? this._private.autounselectify : (this._private.autounselectify = !!e19, this);
  }, selectionType: function(e19) {
    var t14 = this._private;
    return null == t14.selectionType && (t14.selectionType = "single"), void 0 === e19 ? t14.selectionType : ("additive" !== e19 && "single" !== e19 || (t14.selectionType = e19), this);
  }, panningEnabled: function(e19) {
    return void 0 === e19 ? this._private.panningEnabled : (this._private.panningEnabled = !!e19, this);
  }, userPanningEnabled: function(e19) {
    return void 0 === e19 ? this._private.userPanningEnabled : (this._private.userPanningEnabled = !!e19, this);
  }, zoomingEnabled: function(e19) {
    return void 0 === e19 ? this._private.zoomingEnabled : (this._private.zoomingEnabled = !!e19, this);
  }, userZoomingEnabled: function(e19) {
    return void 0 === e19 ? this._private.userZoomingEnabled : (this._private.userZoomingEnabled = !!e19, this);
  }, boxSelectionEnabled: function(e19) {
    return void 0 === e19 ? this._private.boxSelectionEnabled : (this._private.boxSelectionEnabled = !!e19, this);
  }, pan: function() {
    var e19, t14, n11, r8, a8, i9 = arguments, o11 = this._private.pan;
    switch (i9.length) {
      case 0:
        return o11;
      case 1:
        if (M6(i9[0]))
          return o11[e19 = i9[0]];
        if (N6(i9[0])) {
          if (!this._private.panningEnabled)
            return this;
          r8 = (n11 = i9[0]).x, a8 = n11.y, I6(r8) && (o11.x = r8), I6(a8) && (o11.y = a8), this.emit("pan viewport");
        }
        break;
      case 2:
        if (!this._private.panningEnabled)
          return this;
        t14 = i9[1], "x" !== (e19 = i9[0]) && "y" !== e19 || !I6(t14) || (o11[e19] = t14), this.emit("pan viewport");
    }
    return this.notify("viewport"), this;
  }, panBy: function(e19, t14) {
    var n11, r8, a8, i9, o11, s10 = arguments, l10 = this._private.pan;
    if (!this._private.panningEnabled)
      return this;
    switch (s10.length) {
      case 1:
        N6(e19) && (i9 = (a8 = s10[0]).x, o11 = a8.y, I6(i9) && (l10.x += i9), I6(o11) && (l10.y += o11), this.emit("pan viewport"));
        break;
      case 2:
        r8 = t14, "x" !== (n11 = e19) && "y" !== n11 || !I6(r8) || (l10[n11] += r8), this.emit("pan viewport");
    }
    return this.notify("viewport"), this;
  }, fit: function(e19, t14) {
    var n11 = this.getFitViewport(e19, t14);
    if (n11) {
      var r8 = this._private;
      r8.zoom = n11.zoom, r8.pan = n11.pan, this.emit("pan zoom viewport"), this.notify("viewport");
    }
    return this;
  }, getFitViewport: function(e19, t14) {
    if (I6(e19) && void 0 === t14 && (t14 = e19, e19 = void 0), this._private.panningEnabled && this._private.zoomingEnabled) {
      var n11, r8;
      if (M6(e19)) {
        var a8 = e19;
        e19 = this.$(a8);
      } else if (N6(r8 = e19) && I6(r8.x1) && I6(r8.x2) && I6(r8.y1) && I6(r8.y2)) {
        var i9 = e19;
        (n11 = { x1: i9.x1, y1: i9.y1, x2: i9.x2, y2: i9.y2 }).w = n11.x2 - n11.x1, n11.h = n11.y2 - n11.y1;
      } else
        L5(e19) || (e19 = this.mutableElements());
      if (!L5(e19) || !e19.empty()) {
        n11 = n11 || e19.boundingBox();
        var o11, s10 = this.width(), l10 = this.height();
        if (t14 = I6(t14) ? t14 : 0, !isNaN(s10) && !isNaN(l10) && s10 > 0 && l10 > 0 && !isNaN(n11.w) && !isNaN(n11.h) && n11.w > 0 && n11.h > 0)
          return { zoom: o11 = (o11 = (o11 = Math.min((s10 - 2 * t14) / n11.w, (l10 - 2 * t14) / n11.h)) > this._private.maxZoom ? this._private.maxZoom : o11) < this._private.minZoom ? this._private.minZoom : o11, pan: { x: (s10 - o11 * (n11.x1 + n11.x2)) / 2, y: (l10 - o11 * (n11.y1 + n11.y2)) / 2 } };
      }
    }
  }, zoomRange: function(e19, t14) {
    var n11 = this._private;
    if (null == t14) {
      var r8 = e19;
      e19 = r8.min, t14 = r8.max;
    }
    return I6(e19) && I6(t14) && e19 <= t14 ? (n11.minZoom = e19, n11.maxZoom = t14) : I6(e19) && void 0 === t14 && e19 <= n11.maxZoom ? n11.minZoom = e19 : I6(t14) && void 0 === e19 && t14 >= n11.minZoom && (n11.maxZoom = t14), this;
  }, minZoom: function(e19) {
    return void 0 === e19 ? this._private.minZoom : this.zoomRange({ min: e19 });
  }, maxZoom: function(e19) {
    return void 0 === e19 ? this._private.maxZoom : this.zoomRange({ max: e19 });
  }, getZoomedViewport: function(e19) {
    var t14, n11, r8 = this._private, a8 = r8.pan, i9 = r8.zoom, o11 = false;
    if (r8.zoomingEnabled || (o11 = true), I6(e19) ? n11 = e19 : N6(e19) && (n11 = e19.level, null != e19.position ? t14 = at4(e19.position, i9, a8) : null != e19.renderedPosition && (t14 = e19.renderedPosition), null == t14 || r8.panningEnabled || (o11 = true)), n11 = (n11 = n11 > r8.maxZoom ? r8.maxZoom : n11) < r8.minZoom ? r8.minZoom : n11, o11 || !I6(n11) || n11 === i9 || null != t14 && (!I6(t14.x) || !I6(t14.y)))
      return null;
    if (null != t14) {
      var s10 = a8, l10 = i9, u9 = n11;
      return { zoomed: true, panned: true, zoom: u9, pan: { x: -u9 / l10 * (t14.x - s10.x) + t14.x, y: -u9 / l10 * (t14.y - s10.y) + t14.y } };
    }
    return { zoomed: true, panned: false, zoom: n11, pan: a8 };
  }, zoom: function(e19) {
    if (void 0 === e19)
      return this._private.zoom;
    var t14 = this.getZoomedViewport(e19), n11 = this._private;
    return null != t14 && t14.zoomed ? (n11.zoom = t14.zoom, t14.panned && (n11.pan.x = t14.pan.x, n11.pan.y = t14.pan.y), this.emit("zoom" + (t14.panned ? " pan" : "") + " viewport"), this.notify("viewport"), this) : this;
  }, viewport: function(e19) {
    var t14 = this._private, n11 = true, r8 = true, a8 = [], i9 = false, o11 = false;
    if (!e19)
      return this;
    if (I6(e19.zoom) || (n11 = false), N6(e19.pan) || (r8 = false), !n11 && !r8)
      return this;
    if (n11) {
      var s10 = e19.zoom;
      s10 < t14.minZoom || s10 > t14.maxZoom || !t14.zoomingEnabled ? i9 = true : (t14.zoom = s10, a8.push("zoom"));
    }
    if (r8 && (!i9 || !e19.cancelOnFailedZoom) && t14.panningEnabled) {
      var l10 = e19.pan;
      I6(l10.x) && (t14.pan.x = l10.x, o11 = false), I6(l10.y) && (t14.pan.y = l10.y, o11 = false), o11 || a8.push("pan");
    }
    return a8.length > 0 && (a8.push("viewport"), this.emit(a8.join(" ")), this.notify("viewport")), this;
  }, center: function(e19) {
    var t14 = this.getCenterPan(e19);
    return t14 && (this._private.pan = t14, this.emit("pan viewport"), this.notify("viewport")), this;
  }, getCenterPan: function(e19, t14) {
    if (this._private.panningEnabled) {
      if (M6(e19)) {
        var n11 = e19;
        e19 = this.mutableElements().filter(n11);
      } else
        L5(e19) || (e19 = this.mutableElements());
      if (0 !== e19.length) {
        var r8 = e19.boundingBox(), a8 = this.width(), i9 = this.height();
        return { x: (a8 - (t14 = void 0 === t14 ? this._private.zoom : t14) * (r8.x1 + r8.x2)) / 2, y: (i9 - t14 * (r8.y1 + r8.y2)) / 2 };
      }
    }
  }, reset: function() {
    return this._private.panningEnabled && this._private.zoomingEnabled ? (this.viewport({ pan: { x: 0, y: 0 }, zoom: 1 }), this) : this;
  }, invalidateSize: function() {
    this._private.sizeCache = null;
  }, size: function() {
    var e19, t14, n11 = this._private, r8 = n11.container, a8 = this;
    return n11.sizeCache = n11.sizeCache || (r8 ? (e19 = a8.window().getComputedStyle(r8), t14 = function(t15) {
      return parseFloat(e19.getPropertyValue(t15));
    }, { width: r8.clientWidth - t14("padding-left") - t14("padding-right"), height: r8.clientHeight - t14("padding-top") - t14("padding-bottom") }) : { width: 1, height: 1 });
  }, width: function() {
    return this.size().width;
  }, height: function() {
    return this.size().height;
  }, extent: function() {
    var e19 = this._private.pan, t14 = this._private.zoom, n11 = this.renderedExtent(), r8 = { x1: (n11.x1 - e19.x) / t14, x2: (n11.x2 - e19.x) / t14, y1: (n11.y1 - e19.y) / t14, y2: (n11.y2 - e19.y) / t14 };
    return r8.w = r8.x2 - r8.x1, r8.h = r8.y2 - r8.y1, r8;
  }, renderedExtent: function() {
    var e19 = this.width(), t14 = this.height();
    return { x1: 0, y1: 0, x2: e19, y2: t14, w: e19, h: t14 };
  }, multiClickDebounceTime: function(e19) {
    return e19 ? (this._private.multiClickDebounceTime = e19, this) : this._private.multiClickDebounceTime;
  } };
  oo.centre = oo.center, oo.autolockNodes = oo.autolock, oo.autoungrabifyNodes = oo.autoungrabify;
  var so = { data: ur3.data({ field: "data", bindingEvent: "data", allowBinding: true, allowSetting: true, settingEvent: "data", settingTriggersEvent: true, triggerFnName: "trigger", allowGetting: true, updateStyle: true }), removeData: ur3.removeData({ field: "data", event: "data", triggerFnName: "trigger", triggerEvent: true, updateStyle: true }), scratch: ur3.data({ field: "scratch", bindingEvent: "scratch", allowBinding: true, allowSetting: true, settingEvent: "scratch", settingTriggersEvent: true, triggerFnName: "trigger", allowGetting: true, updateStyle: true }), removeScratch: ur3.removeData({ field: "scratch", event: "scratch", triggerFnName: "trigger", triggerEvent: true, updateStyle: true }) };
  so.attr = so.data, so.removeAttr = so.removeData;
  var lo = function(e19) {
    var t14 = this, n11 = (e19 = J4({}, e19)).container;
    n11 && !z5(n11) && z5(n11[0]) && (n11 = n11[0]);
    var r8 = n11 ? n11._cyreg : null;
    (r8 = r8 || {}) && r8.cy && (r8.cy.destroy(), r8 = {});
    var a8 = r8.readies = r8.readies || [];
    n11 && (n11._cyreg = r8), r8.cy = t14;
    var i9 = void 0 !== E5 && void 0 !== n11 && !e19.headless, o11 = e19;
    o11.layout = J4({ name: i9 ? "grid" : "null" }, o11.layout), o11.renderer = J4({ name: i9 ? "canvas" : "null" }, o11.renderer);
    var s10 = function(e20, t15, n12) {
      return void 0 !== t15 ? t15 : void 0 !== n12 ? n12 : e20;
    }, l10 = this._private = { container: n11, ready: false, options: o11, elements: new Ci(this), listeners: [], aniEles: new Ci(this), data: o11.data || {}, scratch: {}, layout: null, renderer: null, destroyed: false, notificationsEnabled: true, minZoom: 1e-50, maxZoom: 1e50, zoomingEnabled: s10(true, o11.zoomingEnabled), userZoomingEnabled: s10(true, o11.userZoomingEnabled), panningEnabled: s10(true, o11.panningEnabled), userPanningEnabled: s10(true, o11.userPanningEnabled), boxSelectionEnabled: s10(true, o11.boxSelectionEnabled), autolock: s10(false, o11.autolock, o11.autolockNodes), autoungrabify: s10(false, o11.autoungrabify, o11.autoungrabifyNodes), autounselectify: s10(false, o11.autounselectify), styleEnabled: void 0 === o11.styleEnabled ? i9 : o11.styleEnabled, zoom: I6(o11.zoom) ? o11.zoom : 1, pan: { x: N6(o11.pan) && I6(o11.pan.x) ? o11.pan.x : 0, y: N6(o11.pan) && I6(o11.pan.y) ? o11.pan.y : 0 }, animation: { current: [], queue: [] }, hasCompoundNodes: false, multiClickDebounceTime: s10(250, o11.multiClickDebounceTime) };
    this.createEmitter(), this.selectionType(o11.selectionType), this.zoomRange({ min: o11.minZoom, max: o11.maxZoom });
    l10.styleEnabled && t14.setStyle([]);
    var u9 = J4({}, o11, o11.renderer);
    t14.initRenderer(u9);
    !function(e20, t15) {
      if (e20.some(q5))
        return rr4.all(e20).then(t15);
      t15(e20);
    }([o11.style, o11.elements], function(e20) {
      var n12 = e20[0], i10 = e20[1];
      l10.styleEnabled && t14.style().append(n12), function(e21, n13, r9) {
        t14.notifications(false);
        var a9 = t14.mutableElements();
        a9.length > 0 && a9.remove(), null != e21 && (N6(e21) || _5(e21)) && t14.add(e21), t14.one("layoutready", function(e22) {
          t14.notifications(true), t14.emit(e22), t14.one("load", n13), t14.emitAndNotify("load");
        }).one("layoutstop", function() {
          t14.one("done", r9), t14.emit("done");
        });
        var i11 = J4({}, t14._private.options.layout);
        i11.eles = t14.elements(), t14.layout(i11).run();
      }(i10, function() {
        t14.startAnimationLoop(), l10.ready = true, B5(o11.ready) && t14.on("ready", o11.ready);
        for (var e21 = 0; e21 < a8.length; e21++) {
          var n13 = a8[e21];
          t14.on("ready", n13);
        }
        r8 && (r8.readies = []), t14.emit("ready");
      }, o11.done);
    });
  };
  var uo = lo.prototype;
  J4(uo, { instanceString: function() {
    return "core";
  }, isReady: function() {
    return this._private.ready;
  }, destroyed: function() {
    return this._private.destroyed;
  }, ready: function(e19) {
    return this.isReady() ? this.emitter().emit("ready", [], e19) : this.on("ready", e19), this;
  }, destroy: function() {
    var e19 = this;
    if (!e19.destroyed())
      return e19.stopAnimationLoop(), e19.destroyRenderer(), this.emit("destroy"), e19._private.destroyed = true, e19;
  }, hasElementWithId: function(e19) {
    return this._private.elements.hasElementWithId(e19);
  }, getElementById: function(e19) {
    return this._private.elements.getElementById(e19);
  }, hasCompoundNodes: function() {
    return this._private.hasCompoundNodes;
  }, headless: function() {
    return this._private.renderer.isHeadless();
  }, styleEnabled: function() {
    return this._private.styleEnabled;
  }, addToPool: function(e19) {
    return this._private.elements.merge(e19), this;
  }, removeFromPool: function(e19) {
    return this._private.elements.unmerge(e19), this;
  }, container: function() {
    return this._private.container || null;
  }, window: function() {
    if (null == this._private.container)
      return E5;
    var e19 = this._private.container.ownerDocument;
    return void 0 === e19 || null == e19 ? E5 : e19.defaultView || E5;
  }, mount: function(e19) {
    if (null != e19) {
      var t14 = this, n11 = t14._private, r8 = n11.options;
      return !z5(e19) && z5(e19[0]) && (e19 = e19[0]), t14.stopAnimationLoop(), t14.destroyRenderer(), n11.container = e19, n11.styleEnabled = true, t14.invalidateSize(), t14.initRenderer(J4({}, r8, r8.renderer, { name: "null" === r8.renderer.name ? "canvas" : r8.renderer.name })), t14.startAnimationLoop(), t14.style(r8.style), t14.emit("mount"), t14;
    }
  }, unmount: function() {
    var e19 = this;
    return e19.stopAnimationLoop(), e19.destroyRenderer(), e19.initRenderer({ name: "null" }), e19.emit("unmount"), e19;
  }, options: function() {
    return Be(this._private.options);
  }, json: function(e19) {
    var t14 = this, n11 = t14._private, r8 = t14.mutableElements();
    if (N6(e19)) {
      if (t14.startBatch(), e19.elements) {
        var a8 = {}, i9 = function(e20, n12) {
          for (var r9 = [], i10 = [], o12 = 0; o12 < e20.length; o12++) {
            var s11 = e20[o12];
            if (s11.data.id) {
              var l11 = "" + s11.data.id, u10 = t14.getElementById(l11);
              a8[l11] = true, 0 !== u10.length ? i10.push({ ele: u10, json: s11 }) : n12 ? (s11.group = n12, r9.push(s11)) : r9.push(s11);
            } else
              Me("cy.json() cannot handle elements without an ID attribute");
          }
          t14.add(r9);
          for (var c10 = 0; c10 < i10.length; c10++) {
            var d11 = i10[c10], h10 = d11.ele, p10 = d11.json;
            h10.json(p10);
          }
        };
        if (_5(e19.elements))
          i9(e19.elements);
        else
          for (var o11 = ["nodes", "edges"], s10 = 0; s10 < o11.length; s10++) {
            var l10 = o11[s10], u9 = e19.elements[l10];
            _5(u9) && i9(u9, l10);
          }
        var c9 = t14.collection();
        r8.filter(function(e20) {
          return !a8[e20.id()];
        }).forEach(function(e20) {
          e20.isParent() ? c9.merge(e20) : e20.remove();
        }), c9.forEach(function(e20) {
          return e20.children().move({ parent: null });
        }), c9.forEach(function(e20) {
          return function(e21) {
            return t14.getElementById(e21.id());
          }(e20).remove();
        });
      }
      e19.style && t14.style(e19.style), null != e19.zoom && e19.zoom !== n11.zoom && t14.zoom(e19.zoom), e19.pan && (e19.pan.x === n11.pan.x && e19.pan.y === n11.pan.y || t14.pan(e19.pan)), e19.data && t14.data(e19.data);
      for (var d10 = ["minZoom", "maxZoom", "zoomingEnabled", "userZoomingEnabled", "panningEnabled", "userPanningEnabled", "boxSelectionEnabled", "autolock", "autoungrabify", "autounselectify", "multiClickDebounceTime"], h9 = 0; h9 < d10.length; h9++) {
        var p9 = d10[h9];
        null != e19[p9] && t14[p9](e19[p9]);
      }
      return t14.endBatch(), this;
    }
    var f10 = {};
    !!e19 ? f10.elements = this.elements().map(function(e20) {
      return e20.json();
    }) : (f10.elements = {}, r8.forEach(function(e20) {
      var t15 = e20.group();
      f10.elements[t15] || (f10.elements[t15] = []), f10.elements[t15].push(e20.json());
    })), this._private.styleEnabled && (f10.style = t14.style().json()), f10.data = Be(t14.data());
    var g8 = n11.options;
    return f10.zoomingEnabled = n11.zoomingEnabled, f10.userZoomingEnabled = n11.userZoomingEnabled, f10.zoom = n11.zoom, f10.minZoom = n11.minZoom, f10.maxZoom = n11.maxZoom, f10.panningEnabled = n11.panningEnabled, f10.userPanningEnabled = n11.userPanningEnabled, f10.pan = Be(n11.pan), f10.boxSelectionEnabled = n11.boxSelectionEnabled, f10.renderer = Be(g8.renderer), f10.hideEdgesOnViewport = g8.hideEdgesOnViewport, f10.textureOnViewport = g8.textureOnViewport, f10.wheelSensitivity = g8.wheelSensitivity, f10.motionBlur = g8.motionBlur, f10.multiClickDebounceTime = g8.multiClickDebounceTime, f10;
  } }), uo.$id = uo.getElementById, [Di, Ri, qi, ji, Yi, Xi, Hi, Ki, io, oo, so].forEach(function(e19) {
    J4(uo, e19);
  });
  var co = { fit: true, directed: false, padding: 30, circle: false, grid: false, spacingFactor: 1.75, boundingBox: void 0, avoidOverlap: true, nodeDimensionsIncludeLabels: false, roots: void 0, depthSort: void 0, animate: false, animationDuration: 500, animationEasing: void 0, animateFilter: function(e19, t14) {
    return true;
  }, ready: void 0, stop: void 0, transform: function(e19, t14) {
    return t14;
  } };
  var ho = { maximal: false, acyclic: false };
  var po = function(e19) {
    return e19.scratch("breadthfirst");
  };
  var fo = function(e19, t14) {
    return e19.scratch("breadthfirst", t14);
  };
  function go(e19) {
    this.options = J4({}, co, ho, e19);
  }
  go.prototype.run = function() {
    var e19, t14 = this.options, n11 = t14, r8 = t14.cy, a8 = n11.eles, i9 = a8.nodes().filter(function(e20) {
      return !e20.isParent();
    }), o11 = a8, s10 = n11.directed, l10 = n11.acyclic || n11.maximal || n11.maximalAdjustments > 0, u9 = vt4(n11.boundingBox ? n11.boundingBox : { x1: 0, y1: 0, w: r8.width(), h: r8.height() });
    if (L5(n11.roots))
      e19 = n11.roots;
    else if (_5(n11.roots)) {
      for (var c9 = [], d10 = 0; d10 < n11.roots.length; d10++) {
        var h9 = n11.roots[d10], p9 = r8.getElementById(h9);
        c9.push(p9);
      }
      e19 = r8.collection(c9);
    } else if (M6(n11.roots))
      e19 = r8.$(n11.roots);
    else if (s10)
      e19 = i9.roots();
    else {
      var f10 = a8.components();
      e19 = r8.collection();
      for (var g8 = function(t15) {
        var n12 = f10[t15], r9 = n12.maxDegree(false), a9 = n12.filter(function(e20) {
          return e20.degree(false) === r9;
        });
        e19 = e19.add(a9);
      }, v11 = 0; v11 < f10.length; v11++)
        g8(v11);
    }
    var y9 = [], m11 = {}, b10 = function(e20, t15) {
      null == y9[t15] && (y9[t15] = []);
      var n12 = y9[t15].length;
      y9[t15].push(e20), fo(e20, { index: n12, depth: t15 });
    };
    o11.bfs({ roots: e19, directed: n11.directed, visit: function(e20, t15, n12, r9, a9) {
      var i10 = e20[0], o12 = i10.id();
      b10(i10, a9), m11[o12] = true;
    } });
    for (var x10 = [], w9 = 0; w9 < i9.length; w9++) {
      var E8 = i9[w9];
      m11[E8.id()] || x10.push(E8);
    }
    var k9 = function(e20) {
      for (var t15 = y9[e20], n12 = 0; n12 < t15.length; n12++) {
        var r9 = t15[n12];
        null != r9 ? fo(r9, { depth: e20, index: n12 }) : (t15.splice(n12, 1), n12--);
      }
    }, C8 = function() {
      for (var e20 = 0; e20 < y9.length; e20++)
        k9(e20);
    }, S7 = function(e20, t15) {
      for (var r9 = po(e20), i10 = e20.incomers().filter(function(e21) {
        return e21.isNode() && a8.has(e21);
      }), o12 = -1, s11 = e20.id(), l11 = 0; l11 < i10.length; l11++) {
        var u10 = i10[l11], c10 = po(u10);
        o12 = Math.max(o12, c10.depth);
      }
      if (r9.depth <= o12) {
        if (!n11.acyclic && t15[s11])
          return null;
        var d11 = o12 + 1;
        return function(e21, t16) {
          var n12 = po(e21), r10 = n12.depth, a9 = n12.index;
          y9[r10][a9] = null, b10(e21, t16);
        }(e20, d11), t15[s11] = d11, true;
      }
      return false;
    };
    if (s10 && l10) {
      var D7 = [], P9 = {}, T8 = function(e20) {
        return D7.push(e20);
      };
      for (i9.forEach(function(e20) {
        return D7.push(e20);
      }); D7.length > 0; ) {
        var B8 = D7.shift(), N7 = S7(B8, P9);
        if (N7)
          B8.outgoers().filter(function(e20) {
            return e20.isNode() && a8.has(e20);
          }).forEach(T8);
        else if (null === N7) {
          Me("Detected double maximal shift for node `" + B8.id() + "`.  Bailing maximal adjustment due to cycle.  Use `options.maximal: true` only on DAGs.");
          break;
        }
      }
    }
    C8();
    var I7 = 0;
    if (n11.avoidOverlap)
      for (var z7 = 0; z7 < i9.length; z7++) {
        var A9 = i9[z7].layoutDimensions(n11), O8 = A9.w, R7 = A9.h;
        I7 = Math.max(I7, O8, R7);
      }
    var V6 = {}, F7 = function(e20) {
      if (V6[e20.id()])
        return V6[e20.id()];
      for (var t15 = po(e20).depth, n12 = e20.neighborhood(), r9 = 0, a9 = 0, o12 = 0; o12 < n12.length; o12++) {
        var s11 = n12[o12];
        if (!s11.isEdge() && !s11.isParent() && i9.has(s11)) {
          var l11 = po(s11);
          if (null != l11) {
            var u10 = l11.index, c10 = l11.depth;
            if (null != u10 && null != c10) {
              var d11 = y9[c10].length;
              c10 < t15 && (r9 += u10 / d11, a9++);
            }
          }
        }
      }
      return r9 /= a9 = Math.max(1, a9), 0 === a9 && (r9 = 0), V6[e20.id()] = r9, r9;
    }, q7 = function(e20, t15) {
      var n12 = F7(e20) - F7(t15);
      return 0 === n12 ? Q4(e20.id(), t15.id()) : n12;
    };
    void 0 !== n11.depthSort && (q7 = n11.depthSort);
    for (var j8 = 0; j8 < y9.length; j8++)
      y9[j8].sort(q7), k9(j8);
    for (var Y5 = [], X5 = 0; X5 < x10.length; X5++)
      Y5.push(x10[X5]);
    y9.unshift(Y5), C8();
    for (var W7 = 0, H8 = 0; H8 < y9.length; H8++)
      W7 = Math.max(y9[H8].length, W7);
    var K5 = u9.x1 + u9.w / 2, G5 = u9.x1 + u9.h / 2, U6 = y9.reduce(function(e20, t15) {
      return Math.max(e20, t15.length);
    }, 0);
    return a8.nodes().layoutPositions(this, n11, function(e20) {
      var t15 = po(e20), r9 = t15.depth, a9 = t15.index, i10 = y9[r9].length, o12 = Math.max(u9.w / ((n11.grid ? U6 : i10) + 1), I7), s11 = Math.max(u9.h / (y9.length + 1), I7), l11 = Math.min(u9.w / 2 / y9.length, u9.h / 2 / y9.length);
      if (l11 = Math.max(l11, I7), n11.circle) {
        var c10 = l11 * r9 + l11 - (y9.length > 0 && y9[0].length <= 3 ? l11 / 2 : 0), d11 = 2 * Math.PI / y9[r9].length * a9;
        return 0 === r9 && 1 === y9[0].length && (c10 = 1), { x: K5 + c10 * Math.cos(d11), y: G5 + c10 * Math.sin(d11) };
      }
      return { x: K5 + (a9 + 1 - (i10 + 1) / 2) * o12, y: (r9 + 1) * s11 };
    }), this;
  };
  var vo = { fit: true, padding: 30, boundingBox: void 0, avoidOverlap: true, nodeDimensionsIncludeLabels: false, spacingFactor: void 0, radius: void 0, startAngle: 1.5 * Math.PI, sweep: void 0, clockwise: true, sort: void 0, animate: false, animationDuration: 500, animationEasing: void 0, animateFilter: function(e19, t14) {
    return true;
  }, ready: void 0, stop: void 0, transform: function(e19, t14) {
    return t14;
  } };
  function yo(e19) {
    this.options = J4({}, vo, e19);
  }
  yo.prototype.run = function() {
    var e19 = this.options, t14 = e19, n11 = e19.cy, r8 = t14.eles, a8 = void 0 !== t14.counterclockwise ? !t14.counterclockwise : t14.clockwise, i9 = r8.nodes().not(":parent");
    t14.sort && (i9 = i9.sort(t14.sort));
    for (var o11, s10 = vt4(t14.boundingBox ? t14.boundingBox : { x1: 0, y1: 0, w: n11.width(), h: n11.height() }), l10 = s10.x1 + s10.w / 2, u9 = s10.y1 + s10.h / 2, c9 = (void 0 === t14.sweep ? 2 * Math.PI - 2 * Math.PI / i9.length : t14.sweep) / Math.max(1, i9.length - 1), d10 = 0, h9 = 0; h9 < i9.length; h9++) {
      var p9 = i9[h9].layoutDimensions(t14), f10 = p9.w, g8 = p9.h;
      d10 = Math.max(d10, f10, g8);
    }
    if (o11 = I6(t14.radius) ? t14.radius : i9.length <= 1 ? 0 : Math.min(s10.h, s10.w) / 2 - d10, i9.length > 1 && t14.avoidOverlap) {
      d10 *= 1.75;
      var v11 = Math.cos(c9) - Math.cos(0), y9 = Math.sin(c9) - Math.sin(0), m11 = Math.sqrt(d10 * d10 / (v11 * v11 + y9 * y9));
      o11 = Math.max(m11, o11);
    }
    return r8.nodes().layoutPositions(this, t14, function(e20, n12) {
      var r9 = t14.startAngle + n12 * c9 * (a8 ? 1 : -1), i10 = o11 * Math.cos(r9), s11 = o11 * Math.sin(r9);
      return { x: l10 + i10, y: u9 + s11 };
    }), this;
  };
  var mo;
  var bo = { fit: true, padding: 30, startAngle: 1.5 * Math.PI, sweep: void 0, clockwise: true, equidistant: false, minNodeSpacing: 10, boundingBox: void 0, avoidOverlap: true, nodeDimensionsIncludeLabels: false, height: void 0, width: void 0, spacingFactor: void 0, concentric: function(e19) {
    return e19.degree();
  }, levelWidth: function(e19) {
    return e19.maxDegree() / 4;
  }, animate: false, animationDuration: 500, animationEasing: void 0, animateFilter: function(e19, t14) {
    return true;
  }, ready: void 0, stop: void 0, transform: function(e19, t14) {
    return t14;
  } };
  function xo(e19) {
    this.options = J4({}, bo, e19);
  }
  xo.prototype.run = function() {
    for (var e19 = this.options, t14 = e19, n11 = void 0 !== t14.counterclockwise ? !t14.counterclockwise : t14.clockwise, r8 = e19.cy, a8 = t14.eles, i9 = a8.nodes().not(":parent"), o11 = vt4(t14.boundingBox ? t14.boundingBox : { x1: 0, y1: 0, w: r8.width(), h: r8.height() }), s10 = o11.x1 + o11.w / 2, l10 = o11.y1 + o11.h / 2, u9 = [], c9 = 0, d10 = 0; d10 < i9.length; d10++) {
      var h9, p9 = i9[d10];
      h9 = t14.concentric(p9), u9.push({ value: h9, node: p9 }), p9._private.scratch.concentric = h9;
    }
    i9.updateStyle();
    for (var f10 = 0; f10 < i9.length; f10++) {
      var g8 = i9[f10].layoutDimensions(t14);
      c9 = Math.max(c9, g8.w, g8.h);
    }
    u9.sort(function(e20, t15) {
      return t15.value - e20.value;
    });
    for (var v11 = t14.levelWidth(i9), y9 = [[]], m11 = y9[0], b10 = 0; b10 < u9.length; b10++) {
      var x10 = u9[b10];
      if (m11.length > 0)
        Math.abs(m11[0].value - x10.value) >= v11 && (m11 = [], y9.push(m11));
      m11.push(x10);
    }
    var w9 = c9 + t14.minNodeSpacing;
    if (!t14.avoidOverlap) {
      var E8 = y9.length > 0 && y9[0].length > 1, k9 = (Math.min(o11.w, o11.h) / 2 - w9) / (y9.length + E8 ? 1 : 0);
      w9 = Math.min(w9, k9);
    }
    for (var C8 = 0, S7 = 0; S7 < y9.length; S7++) {
      var D7 = y9[S7], P9 = void 0 === t14.sweep ? 2 * Math.PI - 2 * Math.PI / D7.length : t14.sweep, T8 = D7.dTheta = P9 / Math.max(1, D7.length - 1);
      if (D7.length > 1 && t14.avoidOverlap) {
        var M8 = Math.cos(T8) - Math.cos(0), B8 = Math.sin(T8) - Math.sin(0), _6 = Math.sqrt(w9 * w9 / (M8 * M8 + B8 * B8));
        C8 = Math.max(_6, C8);
      }
      D7.r = C8, C8 += w9;
    }
    if (t14.equidistant) {
      for (var N7 = 0, I7 = 0, z7 = 0; z7 < y9.length; z7++) {
        var L9 = y9[z7].r - I7;
        N7 = Math.max(N7, L9);
      }
      I7 = 0;
      for (var A9 = 0; A9 < y9.length; A9++) {
        var O8 = y9[A9];
        0 === A9 && (I7 = O8.r), O8.r = I7, I7 += N7;
      }
    }
    for (var R7 = {}, V6 = 0; V6 < y9.length; V6++)
      for (var F7 = y9[V6], q7 = F7.dTheta, j8 = F7.r, Y5 = 0; Y5 < F7.length; Y5++) {
        var X5 = F7[Y5], W7 = t14.startAngle + (n11 ? 1 : -1) * q7 * Y5, H8 = { x: s10 + j8 * Math.cos(W7), y: l10 + j8 * Math.sin(W7) };
        R7[X5.node.id()] = H8;
      }
    return a8.nodes().layoutPositions(this, t14, function(e20) {
      var t15 = e20.id();
      return R7[t15];
    }), this;
  };
  var wo = { ready: function() {
  }, stop: function() {
  }, animate: true, animationEasing: void 0, animationDuration: void 0, animateFilter: function(e19, t14) {
    return true;
  }, animationThreshold: 250, refresh: 20, fit: true, padding: 30, boundingBox: void 0, nodeDimensionsIncludeLabels: false, randomize: false, componentSpacing: 40, nodeRepulsion: function(e19) {
    return 2048;
  }, nodeOverlap: 4, idealEdgeLength: function(e19) {
    return 32;
  }, edgeElasticity: function(e19) {
    return 32;
  }, nestingFactor: 1.2, gravity: 1, numIter: 1e3, initialTemp: 1e3, coolingFactor: 0.99, minTemp: 1 };
  function Eo(e19) {
    this.options = J4({}, wo, e19), this.options.layout = this;
  }
  Eo.prototype.run = function() {
    var e19 = this.options, t14 = e19.cy, n11 = this;
    n11.stopped = false, true !== e19.animate && false !== e19.animate || n11.emit({ type: "layoutstart", layout: n11 }), mo = true === e19.debug;
    var r8 = ko(t14, n11, e19);
    mo && (void 0)(r8), e19.randomize && Do(r8);
    var a8 = le(), i9 = function() {
      To(r8, t14, e19), true === e19.fit && t14.fit(e19.padding);
    }, o11 = function(t15) {
      return !(n11.stopped || t15 >= e19.numIter) && (Mo(r8, e19), r8.temperature = r8.temperature * e19.coolingFactor, !(r8.temperature < e19.minTemp));
    }, s10 = function() {
      if (true === e19.animate || false === e19.animate)
        i9(), n11.one("layoutstop", e19.stop), n11.emit({ type: "layoutstop", layout: n11 });
      else {
        var t15 = e19.eles.nodes(), a9 = Po(r8, e19, t15);
        t15.layoutPositions(n11, e19, a9);
      }
    }, l10 = 0, u9 = true;
    if (true === e19.animate) {
      !function t15() {
        for (var n12 = 0; u9 && n12 < e19.refresh; )
          u9 = o11(l10), l10++, n12++;
        u9 ? (le() - a8 >= e19.animationThreshold && i9(), se(t15)) : (qo(r8, e19), s10());
      }();
    } else {
      for (; u9; )
        u9 = o11(l10), l10++;
      qo(r8, e19), s10();
    }
    return this;
  }, Eo.prototype.stop = function() {
    return this.stopped = true, this.thread && this.thread.stop(), this.emit("layoutstop"), this;
  }, Eo.prototype.destroy = function() {
    return this.thread && this.thread.stop(), this;
  };
  var ko = function(e19, t14, n11) {
    for (var r8 = n11.eles.edges(), a8 = n11.eles.nodes(), i9 = vt4(n11.boundingBox ? n11.boundingBox : { x1: 0, y1: 0, w: e19.width(), h: e19.height() }), o11 = { isCompound: e19.hasCompoundNodes(), layoutNodes: [], idToIndex: {}, nodeSize: a8.size(), graphSet: [], indexToGraph: [], layoutEdges: [], edgeSize: r8.size(), temperature: n11.initialTemp, clientWidth: i9.w, clientHeight: i9.h, boundingBox: i9 }, s10 = n11.eles.components(), l10 = {}, u9 = 0; u9 < s10.length; u9++)
      for (var c9 = s10[u9], d10 = 0; d10 < c9.length; d10++) {
        l10[c9[d10].id()] = u9;
      }
    for (u9 = 0; u9 < o11.nodeSize; u9++) {
      var h9 = (y9 = a8[u9]).layoutDimensions(n11);
      (z7 = {}).isLocked = y9.locked(), z7.id = y9.data("id"), z7.parentId = y9.data("parent"), z7.cmptId = l10[y9.id()], z7.children = [], z7.positionX = y9.position("x"), z7.positionY = y9.position("y"), z7.offsetX = 0, z7.offsetY = 0, z7.height = h9.w, z7.width = h9.h, z7.maxX = z7.positionX + z7.width / 2, z7.minX = z7.positionX - z7.width / 2, z7.maxY = z7.positionY + z7.height / 2, z7.minY = z7.positionY - z7.height / 2, z7.padLeft = parseFloat(y9.style("padding")), z7.padRight = parseFloat(y9.style("padding")), z7.padTop = parseFloat(y9.style("padding")), z7.padBottom = parseFloat(y9.style("padding")), z7.nodeRepulsion = B5(n11.nodeRepulsion) ? n11.nodeRepulsion(y9) : n11.nodeRepulsion, o11.layoutNodes.push(z7), o11.idToIndex[z7.id] = u9;
    }
    var p9 = [], f10 = 0, g8 = -1, v11 = [];
    for (u9 = 0; u9 < o11.nodeSize; u9++) {
      var y9, m11 = (y9 = o11.layoutNodes[u9]).parentId;
      null != m11 ? o11.layoutNodes[o11.idToIndex[m11]].children.push(y9.id) : (p9[++g8] = y9.id, v11.push(y9.id));
    }
    for (o11.graphSet.push(v11); f10 <= g8; ) {
      var b10 = p9[f10++], x10 = o11.idToIndex[b10], w9 = o11.layoutNodes[x10].children;
      if (w9.length > 0) {
        o11.graphSet.push(w9);
        for (u9 = 0; u9 < w9.length; u9++)
          p9[++g8] = w9[u9];
      }
    }
    for (u9 = 0; u9 < o11.graphSet.length; u9++) {
      var E8 = o11.graphSet[u9];
      for (d10 = 0; d10 < E8.length; d10++) {
        var k9 = o11.idToIndex[E8[d10]];
        o11.indexToGraph[k9] = u9;
      }
    }
    for (u9 = 0; u9 < o11.edgeSize; u9++) {
      var C8 = r8[u9], S7 = {};
      S7.id = C8.data("id"), S7.sourceId = C8.data("source"), S7.targetId = C8.data("target");
      var D7 = B5(n11.idealEdgeLength) ? n11.idealEdgeLength(C8) : n11.idealEdgeLength, P9 = B5(n11.edgeElasticity) ? n11.edgeElasticity(C8) : n11.edgeElasticity, T8 = o11.idToIndex[S7.sourceId], M8 = o11.idToIndex[S7.targetId];
      if (o11.indexToGraph[T8] != o11.indexToGraph[M8]) {
        for (var _6 = Co(S7.sourceId, S7.targetId, o11), N7 = o11.graphSet[_6], I7 = 0, z7 = o11.layoutNodes[T8]; -1 === N7.indexOf(z7.id); )
          z7 = o11.layoutNodes[o11.idToIndex[z7.parentId]], I7++;
        for (z7 = o11.layoutNodes[M8]; -1 === N7.indexOf(z7.id); )
          z7 = o11.layoutNodes[o11.idToIndex[z7.parentId]], I7++;
        D7 *= I7 * n11.nestingFactor;
      }
      S7.idealLength = D7, S7.elasticity = P9, o11.layoutEdges.push(S7);
    }
    return o11;
  };
  var Co = function(e19, t14, n11) {
    var r8 = So(e19, t14, 0, n11);
    return 2 > r8.count ? 0 : r8.graph;
  };
  var So = function e13(t14, n11, r8, a8) {
    var i9 = a8.graphSet[r8];
    if (-1 < i9.indexOf(t14) && -1 < i9.indexOf(n11))
      return { count: 2, graph: r8 };
    for (var o11 = 0, s10 = 0; s10 < i9.length; s10++) {
      var l10 = i9[s10], u9 = a8.idToIndex[l10], c9 = a8.layoutNodes[u9].children;
      if (0 !== c9.length) {
        var d10 = e13(t14, n11, a8.indexToGraph[a8.idToIndex[c9[0]]], a8);
        if (0 !== d10.count) {
          if (1 !== d10.count)
            return d10;
          if (2 === ++o11)
            break;
        }
      }
    }
    return { count: o11, graph: r8 };
  };
  var Do = function(e19, t14) {
    for (var n11 = e19.clientWidth, r8 = e19.clientHeight, a8 = 0; a8 < e19.nodeSize; a8++) {
      var i9 = e19.layoutNodes[a8];
      0 !== i9.children.length || i9.isLocked || (i9.positionX = Math.random() * n11, i9.positionY = Math.random() * r8);
    }
  };
  var Po = function(e19, t14, n11) {
    var r8 = e19.boundingBox, a8 = { x1: 1 / 0, x2: -1 / 0, y1: 1 / 0, y2: -1 / 0 };
    return t14.boundingBox && (n11.forEach(function(t15) {
      var n12 = e19.layoutNodes[e19.idToIndex[t15.data("id")]];
      a8.x1 = Math.min(a8.x1, n12.positionX), a8.x2 = Math.max(a8.x2, n12.positionX), a8.y1 = Math.min(a8.y1, n12.positionY), a8.y2 = Math.max(a8.y2, n12.positionY);
    }), a8.w = a8.x2 - a8.x1, a8.h = a8.y2 - a8.y1), function(n12, i9) {
      var o11 = e19.layoutNodes[e19.idToIndex[n12.data("id")]];
      if (t14.boundingBox) {
        var s10 = (o11.positionX - a8.x1) / a8.w, l10 = (o11.positionY - a8.y1) / a8.h;
        return { x: r8.x1 + s10 * r8.w, y: r8.y1 + l10 * r8.h };
      }
      return { x: o11.positionX, y: o11.positionY };
    };
  };
  var To = function(e19, t14, n11) {
    var r8 = n11.layout, a8 = n11.eles.nodes(), i9 = Po(e19, n11, a8);
    a8.positions(i9), true !== e19.ready && (e19.ready = true, r8.one("layoutready", n11.ready), r8.emit({ type: "layoutready", layout: this }));
  };
  var Mo = function(e19, t14, n11) {
    Bo(e19, t14), Lo(e19), Ao(e19, t14), Oo(e19), Ro(e19);
  };
  var Bo = function(e19, t14) {
    for (var n11 = 0; n11 < e19.graphSet.length; n11++)
      for (var r8 = e19.graphSet[n11], a8 = r8.length, i9 = 0; i9 < a8; i9++)
        for (var o11 = e19.layoutNodes[e19.idToIndex[r8[i9]]], s10 = i9 + 1; s10 < a8; s10++) {
          var l10 = e19.layoutNodes[e19.idToIndex[r8[s10]]];
          No(o11, l10, e19, t14);
        }
  };
  var _o = function(e19) {
    return -e19 + 2 * e19 * Math.random();
  };
  var No = function(e19, t14, n11, r8) {
    if (e19.cmptId === t14.cmptId || n11.isCompound) {
      var a8 = t14.positionX - e19.positionX, i9 = t14.positionY - e19.positionY;
      0 === a8 && 0 === i9 && (a8 = _o(1), i9 = _o(1));
      var o11 = Io(e19, t14, a8, i9);
      if (o11 > 0)
        var s10 = (u9 = r8.nodeOverlap * o11) * a8 / (g8 = Math.sqrt(a8 * a8 + i9 * i9)), l10 = u9 * i9 / g8;
      else {
        var u9, c9 = zo(e19, a8, i9), d10 = zo(t14, -1 * a8, -1 * i9), h9 = d10.x - c9.x, p9 = d10.y - c9.y, f10 = h9 * h9 + p9 * p9, g8 = Math.sqrt(f10);
        s10 = (u9 = (e19.nodeRepulsion + t14.nodeRepulsion) / f10) * h9 / g8, l10 = u9 * p9 / g8;
      }
      e19.isLocked || (e19.offsetX -= s10, e19.offsetY -= l10), t14.isLocked || (t14.offsetX += s10, t14.offsetY += l10);
    }
  };
  var Io = function(e19, t14, n11, r8) {
    if (n11 > 0)
      var a8 = e19.maxX - t14.minX;
    else
      a8 = t14.maxX - e19.minX;
    if (r8 > 0)
      var i9 = e19.maxY - t14.minY;
    else
      i9 = t14.maxY - e19.minY;
    return a8 >= 0 && i9 >= 0 ? Math.sqrt(a8 * a8 + i9 * i9) : 0;
  };
  var zo = function(e19, t14, n11) {
    var r8 = e19.positionX, a8 = e19.positionY, i9 = e19.height || 1, o11 = e19.width || 1, s10 = n11 / t14, l10 = i9 / o11, u9 = {};
    return 0 === t14 && 0 < n11 || 0 === t14 && 0 > n11 ? (u9.x = r8, u9.y = a8 + i9 / 2, u9) : 0 < t14 && -1 * l10 <= s10 && s10 <= l10 ? (u9.x = r8 + o11 / 2, u9.y = a8 + o11 * n11 / 2 / t14, u9) : 0 > t14 && -1 * l10 <= s10 && s10 <= l10 ? (u9.x = r8 - o11 / 2, u9.y = a8 - o11 * n11 / 2 / t14, u9) : 0 < n11 && (s10 <= -1 * l10 || s10 >= l10) ? (u9.x = r8 + i9 * t14 / 2 / n11, u9.y = a8 + i9 / 2, u9) : 0 > n11 && (s10 <= -1 * l10 || s10 >= l10) ? (u9.x = r8 - i9 * t14 / 2 / n11, u9.y = a8 - i9 / 2, u9) : u9;
  };
  var Lo = function(e19, t14) {
    for (var n11 = 0; n11 < e19.edgeSize; n11++) {
      var r8 = e19.layoutEdges[n11], a8 = e19.idToIndex[r8.sourceId], i9 = e19.layoutNodes[a8], o11 = e19.idToIndex[r8.targetId], s10 = e19.layoutNodes[o11], l10 = s10.positionX - i9.positionX, u9 = s10.positionY - i9.positionY;
      if (0 !== l10 || 0 !== u9) {
        var c9 = zo(i9, l10, u9), d10 = zo(s10, -1 * l10, -1 * u9), h9 = d10.x - c9.x, p9 = d10.y - c9.y, f10 = Math.sqrt(h9 * h9 + p9 * p9), g8 = Math.pow(r8.idealLength - f10, 2) / r8.elasticity;
        if (0 !== f10)
          var v11 = g8 * h9 / f10, y9 = g8 * p9 / f10;
        else
          v11 = 0, y9 = 0;
        i9.isLocked || (i9.offsetX += v11, i9.offsetY += y9), s10.isLocked || (s10.offsetX -= v11, s10.offsetY -= y9);
      }
    }
  };
  var Ao = function(e19, t14) {
    if (0 !== t14.gravity)
      for (var n11 = 0; n11 < e19.graphSet.length; n11++) {
        var r8 = e19.graphSet[n11], a8 = r8.length;
        if (0 === n11)
          var i9 = e19.clientHeight / 2, o11 = e19.clientWidth / 2;
        else {
          var s10 = e19.layoutNodes[e19.idToIndex[r8[0]]], l10 = e19.layoutNodes[e19.idToIndex[s10.parentId]];
          i9 = l10.positionX, o11 = l10.positionY;
        }
        for (var u9 = 0; u9 < a8; u9++) {
          var c9 = e19.layoutNodes[e19.idToIndex[r8[u9]]];
          if (!c9.isLocked) {
            var d10 = i9 - c9.positionX, h9 = o11 - c9.positionY, p9 = Math.sqrt(d10 * d10 + h9 * h9);
            if (p9 > 1) {
              var f10 = t14.gravity * d10 / p9, g8 = t14.gravity * h9 / p9;
              c9.offsetX += f10, c9.offsetY += g8;
            }
          }
        }
      }
  };
  var Oo = function(e19, t14) {
    var n11 = [], r8 = 0, a8 = -1;
    for (n11.push.apply(n11, e19.graphSet[0]), a8 += e19.graphSet[0].length; r8 <= a8; ) {
      var i9 = n11[r8++], o11 = e19.idToIndex[i9], s10 = e19.layoutNodes[o11], l10 = s10.children;
      if (0 < l10.length && !s10.isLocked) {
        for (var u9 = s10.offsetX, c9 = s10.offsetY, d10 = 0; d10 < l10.length; d10++) {
          var h9 = e19.layoutNodes[e19.idToIndex[l10[d10]]];
          h9.offsetX += u9, h9.offsetY += c9, n11[++a8] = l10[d10];
        }
        s10.offsetX = 0, s10.offsetY = 0;
      }
    }
  };
  var Ro = function(e19, t14) {
    for (var n11 = 0; n11 < e19.nodeSize; n11++) {
      0 < (a8 = e19.layoutNodes[n11]).children.length && (a8.maxX = void 0, a8.minX = void 0, a8.maxY = void 0, a8.minY = void 0);
    }
    for (n11 = 0; n11 < e19.nodeSize; n11++) {
      if (!(0 < (a8 = e19.layoutNodes[n11]).children.length || a8.isLocked)) {
        var r8 = Vo(a8.offsetX, a8.offsetY, e19.temperature);
        a8.positionX += r8.x, a8.positionY += r8.y, a8.offsetX = 0, a8.offsetY = 0, a8.minX = a8.positionX - a8.width, a8.maxX = a8.positionX + a8.width, a8.minY = a8.positionY - a8.height, a8.maxY = a8.positionY + a8.height, Fo(a8, e19);
      }
    }
    for (n11 = 0; n11 < e19.nodeSize; n11++) {
      var a8;
      0 < (a8 = e19.layoutNodes[n11]).children.length && !a8.isLocked && (a8.positionX = (a8.maxX + a8.minX) / 2, a8.positionY = (a8.maxY + a8.minY) / 2, a8.width = a8.maxX - a8.minX, a8.height = a8.maxY - a8.minY);
    }
  };
  var Vo = function(e19, t14, n11) {
    var r8 = Math.sqrt(e19 * e19 + t14 * t14);
    if (r8 > n11)
      var a8 = { x: n11 * e19 / r8, y: n11 * t14 / r8 };
    else
      a8 = { x: e19, y: t14 };
    return a8;
  };
  var Fo = function e14(t14, n11) {
    var r8 = t14.parentId;
    if (null != r8) {
      var a8 = n11.layoutNodes[n11.idToIndex[r8]], i9 = false;
      return (null == a8.maxX || t14.maxX + a8.padRight > a8.maxX) && (a8.maxX = t14.maxX + a8.padRight, i9 = true), (null == a8.minX || t14.minX - a8.padLeft < a8.minX) && (a8.minX = t14.minX - a8.padLeft, i9 = true), (null == a8.maxY || t14.maxY + a8.padBottom > a8.maxY) && (a8.maxY = t14.maxY + a8.padBottom, i9 = true), (null == a8.minY || t14.minY - a8.padTop < a8.minY) && (a8.minY = t14.minY - a8.padTop, i9 = true), i9 ? e14(a8, n11) : void 0;
    }
  };
  var qo = function(e19, t14) {
    for (var n11 = e19.layoutNodes, r8 = [], a8 = 0; a8 < n11.length; a8++) {
      var i9 = n11[a8], o11 = i9.cmptId;
      (r8[o11] = r8[o11] || []).push(i9);
    }
    var s10 = 0;
    for (a8 = 0; a8 < r8.length; a8++) {
      if (g8 = r8[a8]) {
        g8.x1 = 1 / 0, g8.x2 = -1 / 0, g8.y1 = 1 / 0, g8.y2 = -1 / 0;
        for (var l10 = 0; l10 < g8.length; l10++) {
          var u9 = g8[l10];
          g8.x1 = Math.min(g8.x1, u9.positionX - u9.width / 2), g8.x2 = Math.max(g8.x2, u9.positionX + u9.width / 2), g8.y1 = Math.min(g8.y1, u9.positionY - u9.height / 2), g8.y2 = Math.max(g8.y2, u9.positionY + u9.height / 2);
        }
        g8.w = g8.x2 - g8.x1, g8.h = g8.y2 - g8.y1, s10 += g8.w * g8.h;
      }
    }
    r8.sort(function(e20, t15) {
      return t15.w * t15.h - e20.w * e20.h;
    });
    var c9 = 0, d10 = 0, h9 = 0, p9 = 0, f10 = Math.sqrt(s10) * e19.clientWidth / e19.clientHeight;
    for (a8 = 0; a8 < r8.length; a8++) {
      var g8;
      if (g8 = r8[a8]) {
        for (l10 = 0; l10 < g8.length; l10++) {
          (u9 = g8[l10]).isLocked || (u9.positionX += c9 - g8.x1, u9.positionY += d10 - g8.y1);
        }
        c9 += g8.w + t14.componentSpacing, h9 += g8.w + t14.componentSpacing, p9 = Math.max(p9, g8.h), h9 > f10 && (d10 += p9 + t14.componentSpacing, c9 = 0, h9 = 0, p9 = 0);
      }
    }
  };
  var jo = { fit: true, padding: 30, boundingBox: void 0, avoidOverlap: true, avoidOverlapPadding: 10, nodeDimensionsIncludeLabels: false, spacingFactor: void 0, condense: false, rows: void 0, cols: void 0, position: function(e19) {
  }, sort: void 0, animate: false, animationDuration: 500, animationEasing: void 0, animateFilter: function(e19, t14) {
    return true;
  }, ready: void 0, stop: void 0, transform: function(e19, t14) {
    return t14;
  } };
  function Yo(e19) {
    this.options = J4({}, jo, e19);
  }
  Yo.prototype.run = function() {
    var e19 = this.options, t14 = e19, n11 = e19.cy, r8 = t14.eles, a8 = r8.nodes().not(":parent");
    t14.sort && (a8 = a8.sort(t14.sort));
    var i9 = vt4(t14.boundingBox ? t14.boundingBox : { x1: 0, y1: 0, w: n11.width(), h: n11.height() });
    if (0 === i9.h || 0 === i9.w)
      r8.nodes().layoutPositions(this, t14, function(e20) {
        return { x: i9.x1, y: i9.y1 };
      });
    else {
      var o11 = a8.size(), s10 = Math.sqrt(o11 * i9.h / i9.w), l10 = Math.round(s10), u9 = Math.round(i9.w / i9.h * s10), c9 = function(e20) {
        if (null == e20)
          return Math.min(l10, u9);
        Math.min(l10, u9) == l10 ? l10 = e20 : u9 = e20;
      }, d10 = function(e20) {
        if (null == e20)
          return Math.max(l10, u9);
        Math.max(l10, u9) == l10 ? l10 = e20 : u9 = e20;
      }, h9 = t14.rows, p9 = null != t14.cols ? t14.cols : t14.columns;
      if (null != h9 && null != p9)
        l10 = h9, u9 = p9;
      else if (null != h9 && null == p9)
        l10 = h9, u9 = Math.ceil(o11 / l10);
      else if (null == h9 && null != p9)
        u9 = p9, l10 = Math.ceil(o11 / u9);
      else if (u9 * l10 > o11) {
        var f10 = c9(), g8 = d10();
        (f10 - 1) * g8 >= o11 ? c9(f10 - 1) : (g8 - 1) * f10 >= o11 && d10(g8 - 1);
      } else
        for (; u9 * l10 < o11; ) {
          var v11 = c9(), y9 = d10();
          (y9 + 1) * v11 >= o11 ? d10(y9 + 1) : c9(v11 + 1);
        }
      var m11 = i9.w / u9, b10 = i9.h / l10;
      if (t14.condense && (m11 = 0, b10 = 0), t14.avoidOverlap)
        for (var x10 = 0; x10 < a8.length; x10++) {
          var w9 = a8[x10], E8 = w9._private.position;
          null != E8.x && null != E8.y || (E8.x = 0, E8.y = 0);
          var k9 = w9.layoutDimensions(t14), C8 = t14.avoidOverlapPadding, S7 = k9.w + C8, D7 = k9.h + C8;
          m11 = Math.max(m11, S7), b10 = Math.max(b10, D7);
        }
      for (var P9 = {}, T8 = function(e20, t15) {
        return !!P9["c-" + e20 + "-" + t15];
      }, M8 = function(e20, t15) {
        P9["c-" + e20 + "-" + t15] = true;
      }, B8 = 0, _6 = 0, N7 = function() {
        ++_6 >= u9 && (_6 = 0, B8++);
      }, I7 = {}, z7 = 0; z7 < a8.length; z7++) {
        var L9 = a8[z7], A9 = t14.position(L9);
        if (A9 && (void 0 !== A9.row || void 0 !== A9.col)) {
          var O8 = { row: A9.row, col: A9.col };
          if (void 0 === O8.col)
            for (O8.col = 0; T8(O8.row, O8.col); )
              O8.col++;
          else if (void 0 === O8.row)
            for (O8.row = 0; T8(O8.row, O8.col); )
              O8.row++;
          I7[L9.id()] = O8, M8(O8.row, O8.col);
        }
      }
      a8.layoutPositions(this, t14, function(e20, t15) {
        var n12, r9;
        if (e20.locked() || e20.isParent())
          return false;
        var a9 = I7[e20.id()];
        if (a9)
          n12 = a9.col * m11 + m11 / 2 + i9.x1, r9 = a9.row * b10 + b10 / 2 + i9.y1;
        else {
          for (; T8(B8, _6); )
            N7();
          n12 = _6 * m11 + m11 / 2 + i9.x1, r9 = B8 * b10 + b10 / 2 + i9.y1, M8(B8, _6), N7();
        }
        return { x: n12, y: r9 };
      });
    }
    return this;
  };
  var Xo = { ready: function() {
  }, stop: function() {
  } };
  function Wo(e19) {
    this.options = J4({}, Xo, e19);
  }
  Wo.prototype.run = function() {
    var e19 = this.options, t14 = e19.eles, n11 = this;
    return e19.cy, n11.emit("layoutstart"), t14.nodes().positions(function() {
      return { x: 0, y: 0 };
    }), n11.one("layoutready", e19.ready), n11.emit("layoutready"), n11.one("layoutstop", e19.stop), n11.emit("layoutstop"), this;
  }, Wo.prototype.stop = function() {
    return this;
  };
  var Ho = { positions: void 0, zoom: void 0, pan: void 0, fit: true, padding: 30, animate: false, animationDuration: 500, animationEasing: void 0, animateFilter: function(e19, t14) {
    return true;
  }, ready: void 0, stop: void 0, transform: function(e19, t14) {
    return t14;
  } };
  function Ko(e19) {
    this.options = J4({}, Ho, e19);
  }
  Ko.prototype.run = function() {
    var e19 = this.options, t14 = e19.eles.nodes(), n11 = B5(e19.positions);
    return t14.layoutPositions(this, e19, function(t15, r8) {
      var a8 = function(t16) {
        if (null == e19.positions)
          return function(e20) {
            return { x: e20.x, y: e20.y };
          }(t16.position());
        if (n11)
          return e19.positions(t16);
        var r9 = e19.positions[t16._private.data.id];
        return null == r9 ? null : r9;
      }(t15);
      return !t15.locked() && null != a8 && a8;
    }), this;
  };
  var Go = { fit: true, padding: 30, boundingBox: void 0, animate: false, animationDuration: 500, animationEasing: void 0, animateFilter: function(e19, t14) {
    return true;
  }, ready: void 0, stop: void 0, transform: function(e19, t14) {
    return t14;
  } };
  function Uo(e19) {
    this.options = J4({}, Go, e19);
  }
  Uo.prototype.run = function() {
    var e19 = this.options, t14 = e19.cy, n11 = e19.eles, r8 = vt4(e19.boundingBox ? e19.boundingBox : { x1: 0, y1: 0, w: t14.width(), h: t14.height() });
    return n11.nodes().layoutPositions(this, e19, function(e20, t15) {
      return { x: r8.x1 + Math.round(Math.random() * r8.w), y: r8.y1 + Math.round(Math.random() * r8.h) };
    }), this;
  };
  var Zo = [{ name: "breadthfirst", impl: go }, { name: "circle", impl: yo }, { name: "concentric", impl: xo }, { name: "cose", impl: Eo }, { name: "grid", impl: Yo }, { name: "null", impl: Wo }, { name: "preset", impl: Ko }, { name: "random", impl: Uo }];
  function $o(e19) {
    this.options = e19, this.notifications = 0;
  }
  var Qo = function() {
  };
  var Jo = function() {
    throw new Error("A headless instance can not render images");
  };
  $o.prototype = { recalculateRenderedStyle: Qo, notify: function() {
    this.notifications++;
  }, init: Qo, isHeadless: function() {
    return true;
  }, png: Jo, jpg: Jo };
  var es = { arrowShapeWidth: 0.3, registerArrowShapes: function() {
    var e19 = this.arrowShapes = {}, t14 = this, n11 = function(e20, t15, n12, r9, a9, i10, o12) {
      var s11 = a9.x - n12 / 2 - o12, l10 = a9.x + n12 / 2 + o12, u9 = a9.y - n12 / 2 - o12, c9 = a9.y + n12 / 2 + o12;
      return s11 <= e20 && e20 <= l10 && u9 <= t15 && t15 <= c9;
    }, r8 = function(e20, t15, n12, r9, a9) {
      var i10 = e20 * Math.cos(r9) - t15 * Math.sin(r9), o12 = (e20 * Math.sin(r9) + t15 * Math.cos(r9)) * n12;
      return { x: i10 * n12 + a9.x, y: o12 + a9.y };
    }, a8 = function(e20, t15, n12, a9) {
      for (var i10 = [], o12 = 0; o12 < e20.length; o12 += 2) {
        var s11 = e20[o12], l10 = e20[o12 + 1];
        i10.push(r8(s11, l10, t15, n12, a9));
      }
      return i10;
    }, i9 = function(e20) {
      for (var t15 = [], n12 = 0; n12 < e20.length; n12++) {
        var r9 = e20[n12];
        t15.push(r9.x, r9.y);
      }
      return t15;
    }, o11 = function(e20) {
      return e20.pstyle("width").pfValue * e20.pstyle("arrow-scale").pfValue * 2;
    }, s10 = function(r9, s11) {
      M6(s11) && (s11 = e19[s11]), e19[r9] = J4({ name: r9, points: [-0.15, -0.3, 0.15, -0.3, 0.15, 0.3, -0.15, 0.3], collide: function(e20, t15, n12, r10, o12, s12) {
        var l10 = i9(a8(this.points, n12 + 2 * s12, r10, o12));
        return Mt4(e20, t15, l10);
      }, roughCollide: n11, draw: function(e20, n12, r10, i10) {
        var o12 = a8(this.points, n12, r10, i10);
        t14.arrowShapeImpl("polygon")(e20, o12);
      }, spacing: function(e20) {
        return 0;
      }, gap: o11 }, s11);
    };
    s10("none", { collide: Ce, roughCollide: Ce, draw: De, spacing: Se, gap: Se }), s10("triangle", { points: [-0.15, -0.3, 0, 0, 0.15, -0.3] }), s10("arrow", "triangle"), s10("triangle-backcurve", { points: e19.triangle.points, controlPoint: [0, -0.15], roughCollide: n11, draw: function(e20, n12, i10, o12, s11) {
      var l10 = a8(this.points, n12, i10, o12), u9 = this.controlPoint, c9 = r8(u9[0], u9[1], n12, i10, o12);
      t14.arrowShapeImpl(this.name)(e20, l10, c9);
    }, gap: function(e20) {
      return 0.8 * o11(e20);
    } }), s10("triangle-tee", { points: [0, 0, 0.15, -0.3, -0.15, -0.3, 0, 0], pointsTee: [-0.15, -0.4, -0.15, -0.5, 0.15, -0.5, 0.15, -0.4], collide: function(e20, t15, n12, r9, o12, s11, l10) {
      var u9 = i9(a8(this.points, n12 + 2 * l10, r9, o12)), c9 = i9(a8(this.pointsTee, n12 + 2 * l10, r9, o12));
      return Mt4(e20, t15, u9) || Mt4(e20, t15, c9);
    }, draw: function(e20, n12, r9, i10, o12) {
      var s11 = a8(this.points, n12, r9, i10), l10 = a8(this.pointsTee, n12, r9, i10);
      t14.arrowShapeImpl(this.name)(e20, s11, l10);
    } }), s10("circle-triangle", { radius: 0.15, pointsTr: [0, -0.15, 0.15, -0.45, -0.15, -0.45, 0, -0.15], collide: function(e20, t15, n12, r9, o12, s11, l10) {
      var u9 = o12, c9 = Math.pow(u9.x - e20, 2) + Math.pow(u9.y - t15, 2) <= Math.pow((n12 + 2 * l10) * this.radius, 2), d10 = i9(a8(this.points, n12 + 2 * l10, r9, o12));
      return Mt4(e20, t15, d10) || c9;
    }, draw: function(e20, n12, r9, i10, o12) {
      var s11 = a8(this.pointsTr, n12, r9, i10);
      t14.arrowShapeImpl(this.name)(e20, s11, i10.x, i10.y, this.radius * n12);
    }, spacing: function(e20) {
      return t14.getArrowWidth(e20.pstyle("width").pfValue, e20.pstyle("arrow-scale").value) * this.radius;
    } }), s10("triangle-cross", { points: [0, 0, 0.15, -0.3, -0.15, -0.3, 0, 0], baseCrossLinePts: [-0.15, -0.4, -0.15, -0.4, 0.15, -0.4, 0.15, -0.4], crossLinePts: function(e20, t15) {
      var n12 = this.baseCrossLinePts.slice(), r9 = t15 / e20;
      return n12[3] = n12[3] - r9, n12[5] = n12[5] - r9, n12;
    }, collide: function(e20, t15, n12, r9, o12, s11, l10) {
      var u9 = i9(a8(this.points, n12 + 2 * l10, r9, o12)), c9 = i9(a8(this.crossLinePts(n12, s11), n12 + 2 * l10, r9, o12));
      return Mt4(e20, t15, u9) || Mt4(e20, t15, c9);
    }, draw: function(e20, n12, r9, i10, o12) {
      var s11 = a8(this.points, n12, r9, i10), l10 = a8(this.crossLinePts(n12, o12), n12, r9, i10);
      t14.arrowShapeImpl(this.name)(e20, s11, l10);
    } }), s10("vee", { points: [-0.15, -0.3, 0, 0, 0.15, -0.3, 0, -0.15], gap: function(e20) {
      return 0.525 * o11(e20);
    } }), s10("circle", { radius: 0.15, collide: function(e20, t15, n12, r9, a9, i10, o12) {
      var s11 = a9;
      return Math.pow(s11.x - e20, 2) + Math.pow(s11.y - t15, 2) <= Math.pow((n12 + 2 * o12) * this.radius, 2);
    }, draw: function(e20, n12, r9, a9, i10) {
      t14.arrowShapeImpl(this.name)(e20, a9.x, a9.y, this.radius * n12);
    }, spacing: function(e20) {
      return t14.getArrowWidth(e20.pstyle("width").pfValue, e20.pstyle("arrow-scale").value) * this.radius;
    } }), s10("tee", { points: [-0.15, 0, -0.15, -0.1, 0.15, -0.1, 0.15, 0], spacing: function(e20) {
      return 1;
    }, gap: function(e20) {
      return 1;
    } }), s10("square", { points: [-0.15, 0, 0.15, 0, 0.15, -0.3, -0.15, -0.3] }), s10("diamond", { points: [-0.15, -0.15, 0, -0.3, 0.15, -0.15, 0, 0], gap: function(e20) {
      return e20.pstyle("width").pfValue * e20.pstyle("arrow-scale").value;
    } }), s10("chevron", { points: [0, 0, -0.15, -0.15, -0.1, -0.2, 0, -0.1, 0.1, -0.2, 0.15, -0.15], gap: function(e20) {
      return 0.95 * e20.pstyle("width").pfValue * e20.pstyle("arrow-scale").value;
    } });
  } };
  var ts = { projectIntoViewport: function(e19, t14) {
    var n11 = this.cy, r8 = this.findContainerClientCoords(), a8 = r8[0], i9 = r8[1], o11 = r8[4], s10 = n11.pan(), l10 = n11.zoom();
    return [((e19 - a8) / o11 - s10.x) / l10, ((t14 - i9) / o11 - s10.y) / l10];
  }, findContainerClientCoords: function() {
    if (this.containerBB)
      return this.containerBB;
    var e19 = this.container, t14 = e19.getBoundingClientRect(), n11 = this.cy.window().getComputedStyle(e19), r8 = function(e20) {
      return parseFloat(n11.getPropertyValue(e20));
    }, a8 = r8("padding-left"), i9 = r8("padding-right"), o11 = r8("padding-top"), s10 = r8("padding-bottom"), l10 = r8("border-left-width"), u9 = r8("border-right-width"), c9 = r8("border-top-width"), d10 = (r8("border-bottom-width"), e19.clientWidth), h9 = e19.clientHeight, p9 = a8 + i9, f10 = o11 + s10, g8 = l10 + u9, v11 = t14.width / (d10 + g8), y9 = d10 - p9, m11 = h9 - f10, b10 = t14.left + a8 + l10, x10 = t14.top + o11 + c9;
    return this.containerBB = [b10, x10, y9, m11, v11];
  }, invalidateContainerClientCoordsCache: function() {
    this.containerBB = null;
  }, findNearestElement: function(e19, t14, n11, r8) {
    return this.findNearestElements(e19, t14, n11, r8)[0];
  }, findNearestElements: function(e19, t14, n11, r8) {
    var a8, i9, o11 = this, s10 = this, l10 = s10.getCachedZSortedEles(), u9 = [], c9 = s10.cy.zoom(), d10 = s10.cy.hasCompoundNodes(), h9 = (r8 ? 24 : 8) / c9, p9 = (r8 ? 8 : 2) / c9, f10 = (r8 ? 8 : 2) / c9, g8 = 1 / 0;
    function v11(e20, t15) {
      if (e20.isNode()) {
        if (i9)
          return;
        i9 = e20, u9.push(e20);
      }
      if (e20.isEdge() && (null == t15 || t15 < g8))
        if (a8) {
          if (a8.pstyle("z-compound-depth").value === e20.pstyle("z-compound-depth").value && a8.pstyle("z-compound-depth").value === e20.pstyle("z-compound-depth").value) {
            for (var n12 = 0; n12 < u9.length; n12++)
              if (u9[n12].isEdge()) {
                u9[n12] = e20, a8 = e20, g8 = null != t15 ? t15 : g8;
                break;
              }
          }
        } else
          u9.push(e20), a8 = e20, g8 = null != t15 ? t15 : g8;
    }
    function y9(n12) {
      var r9 = n12.outerWidth() + 2 * p9, a9 = n12.outerHeight() + 2 * p9, i10 = r9 / 2, l11 = a9 / 2, u10 = n12.position();
      if (u10.x - i10 <= e19 && e19 <= u10.x + i10 && u10.y - l11 <= t14 && t14 <= u10.y + l11 && s10.nodeShapes[o11.getNodeShape(n12)].checkPoint(e19, t14, 0, r9, a9, u10.x, u10.y))
        return v11(n12, 0), true;
    }
    function m11(n12) {
      var r9, a9 = n12._private, i10 = a9.rscratch, l11 = n12.pstyle("width").pfValue, c10 = n12.pstyle("arrow-scale").value, p10 = l11 / 2 + h9, f11 = p10 * p10, g9 = 2 * p10, m12 = a9.source, b11 = a9.target;
      if ("segments" === i10.edgeType || "straight" === i10.edgeType || "haystack" === i10.edgeType) {
        for (var x11 = i10.allpts, w10 = 0; w10 + 3 < x11.length; w10 += 2)
          if (St4(e19, t14, x11[w10], x11[w10 + 1], x11[w10 + 2], x11[w10 + 3], g9) && f11 > (r9 = Tt4(e19, t14, x11[w10], x11[w10 + 1], x11[w10 + 2], x11[w10 + 3])))
            return v11(n12, r9), true;
      } else if ("bezier" === i10.edgeType || "multibezier" === i10.edgeType || "self" === i10.edgeType || "compound" === i10.edgeType) {
        for (x11 = i10.allpts, w10 = 0; w10 + 5 < i10.allpts.length; w10 += 4)
          if (Dt4(e19, t14, x11[w10], x11[w10 + 1], x11[w10 + 2], x11[w10 + 3], x11[w10 + 4], x11[w10 + 5], g9) && f11 > (r9 = Pt4(e19, t14, x11[w10], x11[w10 + 1], x11[w10 + 2], x11[w10 + 3], x11[w10 + 4], x11[w10 + 5])))
            return v11(n12, r9), true;
      }
      m12 = m12 || a9.source, b11 = b11 || a9.target;
      var E9 = o11.getArrowWidth(l11, c10), k9 = [{ name: "source", x: i10.arrowStartX, y: i10.arrowStartY, angle: i10.srcArrowAngle }, { name: "target", x: i10.arrowEndX, y: i10.arrowEndY, angle: i10.tgtArrowAngle }, { name: "mid-source", x: i10.midX, y: i10.midY, angle: i10.midsrcArrowAngle }, { name: "mid-target", x: i10.midX, y: i10.midY, angle: i10.midtgtArrowAngle }];
      for (w10 = 0; w10 < k9.length; w10++) {
        var C8 = k9[w10], S7 = s10.arrowShapes[n12.pstyle(C8.name + "-arrow-shape").value], D7 = n12.pstyle("width").pfValue;
        if (S7.roughCollide(e19, t14, E9, C8.angle, { x: C8.x, y: C8.y }, D7, h9) && S7.collide(e19, t14, E9, C8.angle, { x: C8.x, y: C8.y }, D7, h9))
          return v11(n12), true;
      }
      d10 && u9.length > 0 && (y9(m12), y9(b11));
    }
    function b10(e20, t15, n12) {
      return Oe(e20, t15, n12);
    }
    function x10(n12, r9) {
      var a9, i10 = n12._private, o12 = f10;
      a9 = r9 ? r9 + "-" : "", n12.boundingBox();
      var s11 = i10.labelBounds[r9 || "main"], l11 = n12.pstyle(a9 + "label").value;
      if ("yes" === n12.pstyle("text-events").strValue && l11) {
        var u10 = b10(i10.rscratch, "labelX", r9), c10 = b10(i10.rscratch, "labelY", r9), d11 = b10(i10.rscratch, "labelAngle", r9), h10 = n12.pstyle(a9 + "text-margin-x").pfValue, p10 = n12.pstyle(a9 + "text-margin-y").pfValue, g9 = s11.x1 - o12 - h10, y10 = s11.x2 + o12 - h10, m12 = s11.y1 - o12 - p10, x11 = s11.y2 + o12 - p10;
        if (d11) {
          var w10 = Math.cos(d11), E9 = Math.sin(d11), k9 = function(e20, t15) {
            return { x: (e20 -= u10) * w10 - (t15 -= c10) * E9 + u10, y: e20 * E9 + t15 * w10 + c10 };
          }, C8 = k9(g9, m12), S7 = k9(g9, x11), D7 = k9(y10, m12), P9 = k9(y10, x11), T8 = [C8.x + h10, C8.y + p10, D7.x + h10, D7.y + p10, P9.x + h10, P9.y + p10, S7.x + h10, S7.y + p10];
          if (Mt4(e19, t14, T8))
            return v11(n12), true;
        } else if (Et4(s11, e19, t14))
          return v11(n12), true;
      }
    }
    n11 && (l10 = l10.interactive);
    for (var w9 = l10.length - 1; w9 >= 0; w9--) {
      var E8 = l10[w9];
      E8.isNode() ? y9(E8) || x10(E8) : m11(E8) || x10(E8) || x10(E8, "source") || x10(E8, "target");
    }
    return u9;
  }, getAllInBox: function(e19, t14, n11, r8) {
    for (var a8, i9, o11 = this.getCachedZSortedEles().interactive, s10 = [], l10 = Math.min(e19, n11), u9 = Math.max(e19, n11), c9 = Math.min(t14, r8), d10 = Math.max(t14, r8), h9 = vt4({ x1: e19 = l10, y1: t14 = c9, x2: n11 = u9, y2: r8 = d10 }), p9 = 0; p9 < o11.length; p9++) {
      var f10 = o11[p9];
      if (f10.isNode()) {
        var g8 = f10, v11 = g8.boundingBox({ includeNodes: true, includeEdges: false, includeLabels: false });
        wt4(h9, v11) && !kt4(v11, h9) && s10.push(g8);
      } else {
        var y9 = f10, m11 = y9._private, b10 = m11.rscratch;
        if (null != b10.startX && null != b10.startY && !Et4(h9, b10.startX, b10.startY))
          continue;
        if (null != b10.endX && null != b10.endY && !Et4(h9, b10.endX, b10.endY))
          continue;
        if ("bezier" === b10.edgeType || "multibezier" === b10.edgeType || "self" === b10.edgeType || "compound" === b10.edgeType || "segments" === b10.edgeType || "haystack" === b10.edgeType) {
          for (var x10 = m11.rstyle.bezierPts || m11.rstyle.linePts || m11.rstyle.haystackPts, w9 = true, E8 = 0; E8 < x10.length; E8++)
            if (a8 = h9, i9 = x10[E8], !Et4(a8, i9.x, i9.y)) {
              w9 = false;
              break;
            }
          w9 && s10.push(y9);
        } else
          "haystack" !== b10.edgeType && "straight" !== b10.edgeType || s10.push(y9);
      }
    }
    return s10;
  } };
  var ns = { calculateArrowAngles: function(e19) {
    var t14, n11, r8, a8, i9, o11, s10 = e19._private.rscratch, l10 = "haystack" === s10.edgeType, u9 = "bezier" === s10.edgeType, c9 = "multibezier" === s10.edgeType, d10 = "segments" === s10.edgeType, h9 = "compound" === s10.edgeType, p9 = "self" === s10.edgeType;
    if (l10 ? (r8 = s10.haystackPts[0], a8 = s10.haystackPts[1], i9 = s10.haystackPts[2], o11 = s10.haystackPts[3]) : (r8 = s10.arrowStartX, a8 = s10.arrowStartY, i9 = s10.arrowEndX, o11 = s10.arrowEndY), g8 = s10.midX, v11 = s10.midY, d10)
      t14 = r8 - s10.segpts[0], n11 = a8 - s10.segpts[1];
    else if (c9 || h9 || p9 || u9) {
      var f10 = s10.allpts;
      t14 = r8 - pt4(f10[0], f10[2], f10[4], 0.1), n11 = a8 - pt4(f10[1], f10[3], f10[5], 0.1);
    } else
      t14 = r8 - g8, n11 = a8 - v11;
    s10.srcArrowAngle = st4(t14, n11);
    var g8 = s10.midX, v11 = s10.midY;
    if (l10 && (g8 = (r8 + i9) / 2, v11 = (a8 + o11) / 2), t14 = i9 - r8, n11 = o11 - a8, d10)
      if ((f10 = s10.allpts).length / 2 % 2 == 0) {
        var y9 = (m11 = f10.length / 2) - 2;
        t14 = f10[m11] - f10[y9], n11 = f10[m11 + 1] - f10[y9 + 1];
      } else {
        y9 = (m11 = f10.length / 2 - 1) - 2;
        var m11, b10 = m11 + 2;
        t14 = f10[m11] - f10[y9], n11 = f10[m11 + 1] - f10[y9 + 1];
      }
    else if (c9 || h9 || p9) {
      var x10, w9, E8, k9, f10 = s10.allpts;
      if (s10.ctrlpts.length / 2 % 2 == 0) {
        var C8 = (S7 = (D7 = f10.length / 2 - 1) + 2) + 2;
        x10 = pt4(f10[D7], f10[S7], f10[C8], 0), w9 = pt4(f10[D7 + 1], f10[S7 + 1], f10[C8 + 1], 0), E8 = pt4(f10[D7], f10[S7], f10[C8], 1e-4), k9 = pt4(f10[D7 + 1], f10[S7 + 1], f10[C8 + 1], 1e-4);
      } else {
        var S7, D7;
        C8 = (S7 = f10.length / 2 - 1) + 2;
        x10 = pt4(f10[D7 = S7 - 2], f10[S7], f10[C8], 0.4999), w9 = pt4(f10[D7 + 1], f10[S7 + 1], f10[C8 + 1], 0.4999), E8 = pt4(f10[D7], f10[S7], f10[C8], 0.5), k9 = pt4(f10[D7 + 1], f10[S7 + 1], f10[C8 + 1], 0.5);
      }
      t14 = E8 - x10, n11 = k9 - w9;
    }
    (s10.midtgtArrowAngle = st4(t14, n11), s10.midDispX = t14, s10.midDispY = n11, t14 *= -1, n11 *= -1, d10) && ((f10 = s10.allpts).length / 2 % 2 == 0 || (t14 = -(f10[b10 = (m11 = f10.length / 2 - 1) + 2] - f10[m11]), n11 = -(f10[b10 + 1] - f10[m11 + 1])));
    if (s10.midsrcArrowAngle = st4(t14, n11), d10)
      t14 = i9 - s10.segpts[s10.segpts.length - 2], n11 = o11 - s10.segpts[s10.segpts.length - 1];
    else if (c9 || h9 || p9 || u9) {
      var P9 = (f10 = s10.allpts).length;
      t14 = i9 - pt4(f10[P9 - 6], f10[P9 - 4], f10[P9 - 2], 0.9), n11 = o11 - pt4(f10[P9 - 5], f10[P9 - 3], f10[P9 - 1], 0.9);
    } else
      t14 = i9 - g8, n11 = o11 - v11;
    s10.tgtArrowAngle = st4(t14, n11);
  } };
  ns.getArrowWidth = ns.getArrowHeight = function(e19, t14) {
    var n11 = this.arrowWidthCache = this.arrowWidthCache || {}, r8 = n11[e19 + ", " + t14];
    return r8 || (r8 = Math.max(Math.pow(13.37 * e19, 0.9), 29) * t14, n11[e19 + ", " + t14] = r8, r8);
  };
  var rs = {};
  function as(e19) {
    var t14 = [];
    if (null != e19) {
      for (var n11 = 0; n11 < e19.length; n11 += 2) {
        var r8 = e19[n11], a8 = e19[n11 + 1];
        t14.push({ x: r8, y: a8 });
      }
      return t14;
    }
  }
  rs.findHaystackPoints = function(e19) {
    for (var t14 = 0; t14 < e19.length; t14++) {
      var n11 = e19[t14], r8 = n11._private, a8 = r8.rscratch;
      if (!a8.haystack) {
        var i9 = 2 * Math.random() * Math.PI;
        a8.source = { x: Math.cos(i9), y: Math.sin(i9) }, i9 = 2 * Math.random() * Math.PI, a8.target = { x: Math.cos(i9), y: Math.sin(i9) };
      }
      var o11 = r8.source, s10 = r8.target, l10 = o11.position(), u9 = s10.position(), c9 = o11.width(), d10 = s10.width(), h9 = o11.height(), p9 = s10.height(), f10 = n11.pstyle("haystack-radius").value / 2;
      a8.haystackPts = a8.allpts = [a8.source.x * c9 * f10 + l10.x, a8.source.y * h9 * f10 + l10.y, a8.target.x * d10 * f10 + u9.x, a8.target.y * p9 * f10 + u9.y], a8.midX = (a8.allpts[0] + a8.allpts[2]) / 2, a8.midY = (a8.allpts[1] + a8.allpts[3]) / 2, a8.edgeType = "haystack", a8.haystack = true, this.storeEdgeProjections(n11), this.calculateArrowAngles(n11), this.recalculateEdgeLabelProjections(n11), this.calculateLabelAngles(n11);
    }
  }, rs.findSegmentsPoints = function(e19, t14) {
    var n11 = e19._private.rscratch, r8 = t14.posPts, a8 = t14.intersectionPts, i9 = t14.vectorNormInverse, o11 = e19.pstyle("edge-distances").value, s10 = e19.pstyle("segment-weights"), l10 = e19.pstyle("segment-distances"), u9 = Math.min(s10.pfValue.length, l10.pfValue.length);
    n11.edgeType = "segments", n11.segpts = [];
    for (var c9 = 0; c9 < u9; c9++) {
      var d10 = s10.pfValue[c9], h9 = l10.pfValue[c9], p9 = 1 - d10, f10 = d10, g8 = "node-position" === o11 ? r8 : a8, v11 = { x: g8.x1 * p9 + g8.x2 * f10, y: g8.y1 * p9 + g8.y2 * f10 };
      n11.segpts.push(v11.x + i9.x * h9, v11.y + i9.y * h9);
    }
  }, rs.findLoopPoints = function(e19, t14, n11, r8) {
    var a8 = e19._private.rscratch, i9 = t14.dirCounts, o11 = t14.srcPos, s10 = e19.pstyle("control-point-distances"), l10 = s10 ? s10.pfValue[0] : void 0, u9 = e19.pstyle("loop-direction").pfValue, c9 = e19.pstyle("loop-sweep").pfValue, d10 = e19.pstyle("control-point-step-size").pfValue;
    a8.edgeType = "self";
    var h9 = n11, p9 = d10;
    r8 && (h9 = 0, p9 = l10);
    var f10 = u9 - Math.PI / 2, g8 = f10 - c9 / 2, v11 = f10 + c9 / 2, y9 = String(u9 + "_" + c9);
    h9 = void 0 === i9[y9] ? i9[y9] = 0 : ++i9[y9], a8.ctrlpts = [o11.x + 1.4 * Math.cos(g8) * p9 * (h9 / 3 + 1), o11.y + 1.4 * Math.sin(g8) * p9 * (h9 / 3 + 1), o11.x + 1.4 * Math.cos(v11) * p9 * (h9 / 3 + 1), o11.y + 1.4 * Math.sin(v11) * p9 * (h9 / 3 + 1)];
  }, rs.findCompoundLoopPoints = function(e19, t14, n11, r8) {
    var a8 = e19._private.rscratch;
    a8.edgeType = "compound";
    var i9 = t14.srcPos, o11 = t14.tgtPos, s10 = t14.srcW, l10 = t14.srcH, u9 = t14.tgtW, c9 = t14.tgtH, d10 = e19.pstyle("control-point-step-size").pfValue, h9 = e19.pstyle("control-point-distances"), p9 = h9 ? h9.pfValue[0] : void 0, f10 = n11, g8 = d10;
    r8 && (f10 = 0, g8 = p9);
    var v11 = { x: i9.x - s10 / 2, y: i9.y - l10 / 2 }, y9 = { x: o11.x - u9 / 2, y: o11.y - c9 / 2 }, m11 = { x: Math.min(v11.x, y9.x), y: Math.min(v11.y, y9.y) }, b10 = Math.max(0.5, Math.log(0.01 * s10)), x10 = Math.max(0.5, Math.log(0.01 * u9));
    a8.ctrlpts = [m11.x, m11.y - (1 + Math.pow(50, 1.12) / 100) * g8 * (f10 / 3 + 1) * b10, m11.x - (1 + Math.pow(50, 1.12) / 100) * g8 * (f10 / 3 + 1) * x10, m11.y];
  }, rs.findStraightEdgePoints = function(e19) {
    e19._private.rscratch.edgeType = "straight";
  }, rs.findBezierPoints = function(e19, t14, n11, r8, a8) {
    var i9 = e19._private.rscratch, o11 = t14.vectorNormInverse, s10 = t14.posPts, l10 = t14.intersectionPts, u9 = e19.pstyle("edge-distances").value, c9 = e19.pstyle("control-point-step-size").pfValue, d10 = e19.pstyle("control-point-distances"), h9 = e19.pstyle("control-point-weights"), p9 = d10 && h9 ? Math.min(d10.value.length, h9.value.length) : 1, f10 = d10 ? d10.pfValue[0] : void 0, g8 = h9.value[0], v11 = r8;
    i9.edgeType = v11 ? "multibezier" : "bezier", i9.ctrlpts = [];
    for (var y9 = 0; y9 < p9; y9++) {
      var m11 = (0.5 - t14.eles.length / 2 + n11) * c9 * (a8 ? -1 : 1), b10 = void 0, x10 = ut4(m11);
      v11 && (f10 = d10 ? d10.pfValue[y9] : c9, g8 = h9.value[y9]);
      var w9 = void 0 !== (b10 = r8 ? f10 : void 0 !== f10 ? x10 * f10 : void 0) ? b10 : m11, E8 = 1 - g8, k9 = g8, C8 = "node-position" === u9 ? s10 : l10, S7 = { x: C8.x1 * E8 + C8.x2 * k9, y: C8.y1 * E8 + C8.y2 * k9 };
      i9.ctrlpts.push(S7.x + o11.x * w9, S7.y + o11.y * w9);
    }
  }, rs.findTaxiPoints = function(e19, t14) {
    var n11 = e19._private.rscratch;
    n11.edgeType = "segments";
    var r8 = "vertical", a8 = "horizontal", i9 = "leftward", o11 = "rightward", s10 = "downward", l10 = "upward", u9 = t14.posPts, c9 = t14.srcW, d10 = t14.srcH, h9 = t14.tgtW, p9 = t14.tgtH, f10 = "node-position" !== e19.pstyle("edge-distances").value, g8 = e19.pstyle("taxi-direction").value, v11 = g8, y9 = e19.pstyle("taxi-turn"), m11 = "%" === y9.units, b10 = y9.pfValue, x10 = b10 < 0, w9 = e19.pstyle("taxi-turn-min-distance").pfValue, E8 = f10 ? (c9 + h9) / 2 : 0, k9 = f10 ? (d10 + p9) / 2 : 0, C8 = u9.x2 - u9.x1, S7 = u9.y2 - u9.y1, D7 = function(e20, t15) {
      return e20 > 0 ? Math.max(e20 - t15, 0) : Math.min(e20 + t15, 0);
    }, P9 = D7(C8, E8), T8 = D7(S7, k9), M8 = false;
    "auto" === v11 ? g8 = Math.abs(P9) > Math.abs(T8) ? a8 : r8 : v11 === l10 || v11 === s10 ? (g8 = r8, M8 = true) : v11 !== i9 && v11 !== o11 || (g8 = a8, M8 = true);
    var B8, _6 = g8 === r8, N7 = _6 ? T8 : P9, I7 = _6 ? S7 : C8, z7 = ut4(I7), L9 = false;
    (M8 && (m11 || x10) || !(v11 === s10 && I7 < 0 || v11 === l10 && I7 > 0 || v11 === i9 && I7 > 0 || v11 === o11 && I7 < 0) || (N7 = (z7 *= -1) * Math.abs(N7), L9 = true), m11) ? B8 = (b10 < 0 ? 1 + b10 : b10) * N7 : B8 = (b10 < 0 ? N7 : 0) + b10 * z7;
    var A9 = function(e20) {
      return Math.abs(e20) < w9 || Math.abs(e20) >= Math.abs(N7);
    }, O8 = A9(B8), R7 = A9(Math.abs(N7) - Math.abs(B8));
    if ((O8 || R7) && !L9)
      if (_6) {
        var V6 = Math.abs(I7) <= d10 / 2, F7 = Math.abs(C8) <= h9 / 2;
        if (V6) {
          var q7 = (u9.x1 + u9.x2) / 2, j8 = u9.y1, Y5 = u9.y2;
          n11.segpts = [q7, j8, q7, Y5];
        } else if (F7) {
          var X5 = (u9.y1 + u9.y2) / 2, W7 = u9.x1, H8 = u9.x2;
          n11.segpts = [W7, X5, H8, X5];
        } else
          n11.segpts = [u9.x1, u9.y2];
      } else {
        var K5 = Math.abs(I7) <= c9 / 2, G5 = Math.abs(S7) <= p9 / 2;
        if (K5) {
          var U6 = (u9.y1 + u9.y2) / 2, Z5 = u9.x1, $6 = u9.x2;
          n11.segpts = [Z5, U6, $6, U6];
        } else if (G5) {
          var Q5 = (u9.x1 + u9.x2) / 2, J5 = u9.y1, ee2 = u9.y2;
          n11.segpts = [Q5, J5, Q5, ee2];
        } else
          n11.segpts = [u9.x2, u9.y1];
      }
    else if (_6) {
      var te2 = u9.y1 + B8 + (f10 ? d10 / 2 * z7 : 0), ne2 = u9.x1, re2 = u9.x2;
      n11.segpts = [ne2, te2, re2, te2];
    } else {
      var ae2 = u9.x1 + B8 + (f10 ? c9 / 2 * z7 : 0), ie2 = u9.y1, oe2 = u9.y2;
      n11.segpts = [ae2, ie2, ae2, oe2];
    }
  }, rs.tryToCorrectInvalidPoints = function(e19, t14) {
    var n11 = e19._private.rscratch;
    if ("bezier" === n11.edgeType) {
      var r8 = t14.srcPos, a8 = t14.tgtPos, i9 = t14.srcW, o11 = t14.srcH, s10 = t14.tgtW, l10 = t14.tgtH, u9 = t14.srcShape, c9 = t14.tgtShape, d10 = !I6(n11.startX) || !I6(n11.startY), h9 = !I6(n11.arrowStartX) || !I6(n11.arrowStartY), p9 = !I6(n11.endX) || !I6(n11.endY), f10 = !I6(n11.arrowEndX) || !I6(n11.arrowEndY), g8 = 3 * (this.getArrowWidth(e19.pstyle("width").pfValue, e19.pstyle("arrow-scale").value) * this.arrowShapeWidth), v11 = ct4({ x: n11.ctrlpts[0], y: n11.ctrlpts[1] }, { x: n11.startX, y: n11.startY }), y9 = v11 < g8, m11 = ct4({ x: n11.ctrlpts[0], y: n11.ctrlpts[1] }, { x: n11.endX, y: n11.endY }), b10 = m11 < g8, x10 = false;
      if (d10 || h9 || y9) {
        x10 = true;
        var w9 = { x: n11.ctrlpts[0] - r8.x, y: n11.ctrlpts[1] - r8.y }, E8 = Math.sqrt(w9.x * w9.x + w9.y * w9.y), k9 = { x: w9.x / E8, y: w9.y / E8 }, C8 = Math.max(i9, o11), S7 = { x: n11.ctrlpts[0] + 2 * k9.x * C8, y: n11.ctrlpts[1] + 2 * k9.y * C8 }, D7 = u9.intersectLine(r8.x, r8.y, i9, o11, S7.x, S7.y, 0);
        y9 ? (n11.ctrlpts[0] = n11.ctrlpts[0] + k9.x * (g8 - v11), n11.ctrlpts[1] = n11.ctrlpts[1] + k9.y * (g8 - v11)) : (n11.ctrlpts[0] = D7[0] + k9.x * g8, n11.ctrlpts[1] = D7[1] + k9.y * g8);
      }
      if (p9 || f10 || b10) {
        x10 = true;
        var P9 = { x: n11.ctrlpts[0] - a8.x, y: n11.ctrlpts[1] - a8.y }, T8 = Math.sqrt(P9.x * P9.x + P9.y * P9.y), M8 = { x: P9.x / T8, y: P9.y / T8 }, B8 = Math.max(i9, o11), _6 = { x: n11.ctrlpts[0] + 2 * M8.x * B8, y: n11.ctrlpts[1] + 2 * M8.y * B8 }, N7 = c9.intersectLine(a8.x, a8.y, s10, l10, _6.x, _6.y, 0);
        b10 ? (n11.ctrlpts[0] = n11.ctrlpts[0] + M8.x * (g8 - m11), n11.ctrlpts[1] = n11.ctrlpts[1] + M8.y * (g8 - m11)) : (n11.ctrlpts[0] = N7[0] + M8.x * g8, n11.ctrlpts[1] = N7[1] + M8.y * g8);
      }
      x10 && this.findEndpoints(e19);
    }
  }, rs.storeAllpts = function(e19) {
    var t14 = e19._private.rscratch;
    if ("multibezier" === t14.edgeType || "bezier" === t14.edgeType || "self" === t14.edgeType || "compound" === t14.edgeType) {
      t14.allpts = [], t14.allpts.push(t14.startX, t14.startY);
      for (var n11 = 0; n11 + 1 < t14.ctrlpts.length; n11 += 2)
        t14.allpts.push(t14.ctrlpts[n11], t14.ctrlpts[n11 + 1]), n11 + 3 < t14.ctrlpts.length && t14.allpts.push((t14.ctrlpts[n11] + t14.ctrlpts[n11 + 2]) / 2, (t14.ctrlpts[n11 + 1] + t14.ctrlpts[n11 + 3]) / 2);
      var r8;
      t14.allpts.push(t14.endX, t14.endY), t14.ctrlpts.length / 2 % 2 == 0 ? (r8 = t14.allpts.length / 2 - 1, t14.midX = t14.allpts[r8], t14.midY = t14.allpts[r8 + 1]) : (r8 = t14.allpts.length / 2 - 3, 0.5, t14.midX = pt4(t14.allpts[r8], t14.allpts[r8 + 2], t14.allpts[r8 + 4], 0.5), t14.midY = pt4(t14.allpts[r8 + 1], t14.allpts[r8 + 3], t14.allpts[r8 + 5], 0.5));
    } else if ("straight" === t14.edgeType)
      t14.allpts = [t14.startX, t14.startY, t14.endX, t14.endY], t14.midX = (t14.startX + t14.endX + t14.arrowStartX + t14.arrowEndX) / 4, t14.midY = (t14.startY + t14.endY + t14.arrowStartY + t14.arrowEndY) / 4;
    else if ("segments" === t14.edgeType)
      if (t14.allpts = [], t14.allpts.push(t14.startX, t14.startY), t14.allpts.push.apply(t14.allpts, t14.segpts), t14.allpts.push(t14.endX, t14.endY), t14.segpts.length % 4 == 0) {
        var a8 = t14.segpts.length / 2, i9 = a8 - 2;
        t14.midX = (t14.segpts[i9] + t14.segpts[a8]) / 2, t14.midY = (t14.segpts[i9 + 1] + t14.segpts[a8 + 1]) / 2;
      } else {
        var o11 = t14.segpts.length / 2 - 1;
        t14.midX = t14.segpts[o11], t14.midY = t14.segpts[o11 + 1];
      }
  }, rs.checkForInvalidEdgeWarning = function(e19) {
    var t14 = e19[0]._private.rscratch;
    t14.nodesOverlap || I6(t14.startX) && I6(t14.startY) && I6(t14.endX) && I6(t14.endY) ? t14.loggedErr = false : t14.loggedErr || (t14.loggedErr = true, Me("Edge `" + e19.id() + "` has invalid endpoints and so it is impossible to draw.  Adjust your edge style (e.g. control points) accordingly or use an alternative edge type.  This is expected behaviour when the source node and the target node overlap."));
  }, rs.findEdgeControlPoints = function(e19) {
    var t14 = this;
    if (e19 && 0 !== e19.length) {
      for (var n11 = this, r8 = n11.cy.hasCompoundNodes(), a8 = { map: new Ve(), get: function(e20) {
        var t15 = this.map.get(e20[0]);
        return null != t15 ? t15.get(e20[1]) : null;
      }, set: function(e20, t15) {
        var n12 = this.map.get(e20[0]);
        null == n12 && (n12 = new Ve(), this.map.set(e20[0], n12)), n12.set(e20[1], t15);
      } }, i9 = [], o11 = [], s10 = 0; s10 < e19.length; s10++) {
        var l10 = e19[s10], u9 = l10._private, c9 = l10.pstyle("curve-style").value;
        if (!l10.removed() && l10.takesUpSpace())
          if ("haystack" !== c9) {
            var d10 = "unbundled-bezier" === c9 || "segments" === c9 || "straight" === c9 || "straight-triangle" === c9 || "taxi" === c9, h9 = "unbundled-bezier" === c9 || "bezier" === c9, p9 = u9.source, f10 = u9.target, g8 = [p9.poolIndex(), f10.poolIndex()].sort(), v11 = a8.get(g8);
            null == v11 && (v11 = { eles: [] }, a8.set(g8, v11), i9.push(g8)), v11.eles.push(l10), d10 && (v11.hasUnbundled = true), h9 && (v11.hasBezier = true);
          } else
            o11.push(l10);
      }
      for (var y9 = function(e20) {
        var o12 = i9[e20], s11 = a8.get(o12), l11 = void 0;
        if (!s11.hasUnbundled) {
          var u10 = s11.eles[0].parallelEdges().filter(function(e21) {
            return e21.isBundledBezier();
          });
          Ae(s11.eles), u10.forEach(function(e21) {
            return s11.eles.push(e21);
          }), s11.eles.sort(function(e21, t15) {
            return e21.poolIndex() - t15.poolIndex();
          });
        }
        var c10 = s11.eles[0], d11 = c10.source(), h10 = c10.target();
        if (d11.poolIndex() > h10.poolIndex()) {
          var p10 = d11;
          d11 = h10, h10 = p10;
        }
        var f11 = s11.srcPos = d11.position(), g9 = s11.tgtPos = h10.position(), v12 = s11.srcW = d11.outerWidth(), y10 = s11.srcH = d11.outerHeight(), m12 = s11.tgtW = h10.outerWidth(), b10 = s11.tgtH = h10.outerHeight(), x10 = s11.srcShape = n11.nodeShapes[t14.getNodeShape(d11)], w9 = s11.tgtShape = n11.nodeShapes[t14.getNodeShape(h10)];
        s11.dirCounts = { north: 0, west: 0, south: 0, east: 0, northwest: 0, southwest: 0, northeast: 0, southeast: 0 };
        for (var E8 = 0; E8 < s11.eles.length; E8++) {
          var k9 = s11.eles[E8], C8 = k9[0]._private.rscratch, S7 = k9.pstyle("curve-style").value, D7 = "unbundled-bezier" === S7 || "segments" === S7 || "taxi" === S7, P9 = !d11.same(k9.source());
          if (!s11.calculatedIntersection && d11 !== h10 && (s11.hasBezier || s11.hasUnbundled)) {
            s11.calculatedIntersection = true;
            var T8 = x10.intersectLine(f11.x, f11.y, v12, y10, g9.x, g9.y, 0), M8 = s11.srcIntn = T8, B8 = w9.intersectLine(g9.x, g9.y, m12, b10, f11.x, f11.y, 0), _6 = s11.tgtIntn = B8, N7 = s11.intersectionPts = { x1: T8[0], x2: B8[0], y1: T8[1], y2: B8[1] }, z7 = s11.posPts = { x1: f11.x, x2: g9.x, y1: f11.y, y2: g9.y }, L9 = B8[1] - T8[1], A9 = B8[0] - T8[0], O8 = Math.sqrt(A9 * A9 + L9 * L9), R7 = s11.vector = { x: A9, y: L9 }, V6 = s11.vectorNorm = { x: R7.x / O8, y: R7.y / O8 }, F7 = { x: -V6.y, y: V6.x };
            s11.nodesOverlap = !I6(O8) || w9.checkPoint(T8[0], T8[1], 0, m12, b10, g9.x, g9.y) || x10.checkPoint(B8[0], B8[1], 0, v12, y10, f11.x, f11.y), s11.vectorNormInverse = F7, l11 = { nodesOverlap: s11.nodesOverlap, dirCounts: s11.dirCounts, calculatedIntersection: true, hasBezier: s11.hasBezier, hasUnbundled: s11.hasUnbundled, eles: s11.eles, srcPos: g9, tgtPos: f11, srcW: m12, srcH: b10, tgtW: v12, tgtH: y10, srcIntn: _6, tgtIntn: M8, srcShape: w9, tgtShape: x10, posPts: { x1: z7.x2, y1: z7.y2, x2: z7.x1, y2: z7.y1 }, intersectionPts: { x1: N7.x2, y1: N7.y2, x2: N7.x1, y2: N7.y1 }, vector: { x: -R7.x, y: -R7.y }, vectorNorm: { x: -V6.x, y: -V6.y }, vectorNormInverse: { x: -F7.x, y: -F7.y } };
          }
          var q7 = P9 ? l11 : s11;
          C8.nodesOverlap = q7.nodesOverlap, C8.srcIntn = q7.srcIntn, C8.tgtIntn = q7.tgtIntn, r8 && (d11.isParent() || d11.isChild() || h10.isParent() || h10.isChild()) && (d11.parents().anySame(h10) || h10.parents().anySame(d11) || d11.same(h10) && d11.isParent()) ? t14.findCompoundLoopPoints(k9, q7, E8, D7) : d11 === h10 ? t14.findLoopPoints(k9, q7, E8, D7) : "segments" === S7 ? t14.findSegmentsPoints(k9, q7) : "taxi" === S7 ? t14.findTaxiPoints(k9, q7) : "straight" === S7 || !D7 && s11.eles.length % 2 == 1 && E8 === Math.floor(s11.eles.length / 2) ? t14.findStraightEdgePoints(k9) : t14.findBezierPoints(k9, q7, E8, D7, P9), t14.findEndpoints(k9), t14.tryToCorrectInvalidPoints(k9, q7), t14.checkForInvalidEdgeWarning(k9), t14.storeAllpts(k9), t14.storeEdgeProjections(k9), t14.calculateArrowAngles(k9), t14.recalculateEdgeLabelProjections(k9), t14.calculateLabelAngles(k9);
        }
      }, m11 = 0; m11 < i9.length; m11++)
        y9(m11);
      this.findHaystackPoints(o11);
    }
  }, rs.getSegmentPoints = function(e19) {
    var t14 = e19[0]._private.rscratch;
    if ("segments" === t14.edgeType)
      return this.recalculateRenderedStyle(e19), as(t14.segpts);
  }, rs.getControlPoints = function(e19) {
    var t14 = e19[0]._private.rscratch, n11 = t14.edgeType;
    if ("bezier" === n11 || "multibezier" === n11 || "self" === n11 || "compound" === n11)
      return this.recalculateRenderedStyle(e19), as(t14.ctrlpts);
  }, rs.getEdgeMidpoint = function(e19) {
    var t14 = e19[0]._private.rscratch;
    return this.recalculateRenderedStyle(e19), { x: t14.midX, y: t14.midY };
  };
  var is = { manualEndptToPx: function(e19, t14) {
    var n11 = e19.position(), r8 = e19.outerWidth(), a8 = e19.outerHeight();
    if (2 === t14.value.length) {
      var i9 = [t14.pfValue[0], t14.pfValue[1]];
      return "%" === t14.units[0] && (i9[0] = i9[0] * r8), "%" === t14.units[1] && (i9[1] = i9[1] * a8), i9[0] += n11.x, i9[1] += n11.y, i9;
    }
    var o11 = t14.pfValue[0];
    o11 = -Math.PI / 2 + o11;
    var s10 = 2 * Math.max(r8, a8), l10 = [n11.x + Math.cos(o11) * s10, n11.y + Math.sin(o11) * s10];
    return this.nodeShapes[this.getNodeShape(e19)].intersectLine(n11.x, n11.y, r8, a8, l10[0], l10[1], 0);
  }, findEndpoints: function(e19) {
    var t14, n11, r8, a8, i9, o11 = this, s10 = e19.source()[0], l10 = e19.target()[0], u9 = s10.position(), c9 = l10.position(), d10 = e19.pstyle("target-arrow-shape").value, h9 = e19.pstyle("source-arrow-shape").value, p9 = e19.pstyle("target-distance-from-node").pfValue, f10 = e19.pstyle("source-distance-from-node").pfValue, g8 = e19.pstyle("curve-style").value, v11 = e19._private.rscratch, y9 = v11.edgeType, m11 = "self" === y9 || "compound" === y9, b10 = "bezier" === y9 || "multibezier" === y9 || m11, x10 = "bezier" !== y9, w9 = "straight" === y9 || "segments" === y9, E8 = "segments" === y9, k9 = b10 || x10 || w9, C8 = m11 || "taxi" === g8, S7 = e19.pstyle("source-endpoint"), D7 = C8 ? "outside-to-node" : S7.value, P9 = e19.pstyle("target-endpoint"), T8 = C8 ? "outside-to-node" : P9.value;
    if (v11.srcManEndpt = S7, v11.tgtManEndpt = P9, b10) {
      var M8 = [v11.ctrlpts[0], v11.ctrlpts[1]];
      n11 = x10 ? [v11.ctrlpts[v11.ctrlpts.length - 2], v11.ctrlpts[v11.ctrlpts.length - 1]] : M8, r8 = M8;
    } else if (w9) {
      var B8 = E8 ? v11.segpts.slice(0, 2) : [c9.x, c9.y];
      n11 = E8 ? v11.segpts.slice(v11.segpts.length - 2) : [u9.x, u9.y], r8 = B8;
    }
    if ("inside-to-node" === T8)
      t14 = [c9.x, c9.y];
    else if (P9.units)
      t14 = this.manualEndptToPx(l10, P9);
    else if ("outside-to-line" === T8)
      t14 = v11.tgtIntn;
    else if ("outside-to-node" === T8 || "outside-to-node-or-label" === T8 ? a8 = n11 : "outside-to-line" !== T8 && "outside-to-line-or-label" !== T8 || (a8 = [u9.x, u9.y]), t14 = o11.nodeShapes[this.getNodeShape(l10)].intersectLine(c9.x, c9.y, l10.outerWidth(), l10.outerHeight(), a8[0], a8[1], 0), "outside-to-node-or-label" === T8 || "outside-to-line-or-label" === T8) {
      var _6 = l10._private.rscratch, N7 = _6.labelWidth, z7 = _6.labelHeight, L9 = _6.labelX, A9 = _6.labelY, O8 = N7 / 2, R7 = z7 / 2, V6 = l10.pstyle("text-valign").value;
      "top" === V6 ? A9 -= R7 : "bottom" === V6 && (A9 += R7);
      var F7 = l10.pstyle("text-halign").value;
      "left" === F7 ? L9 -= O8 : "right" === F7 && (L9 += O8);
      var q7 = Ot4(a8[0], a8[1], [L9 - O8, A9 - R7, L9 + O8, A9 - R7, L9 + O8, A9 + R7, L9 - O8, A9 + R7], c9.x, c9.y);
      if (q7.length > 0) {
        var j8 = u9, Y5 = dt4(j8, ot4(t14)), X5 = dt4(j8, ot4(q7)), W7 = Y5;
        if (X5 < Y5 && (t14 = q7, W7 = X5), q7.length > 2)
          dt4(j8, { x: q7[2], y: q7[3] }) < W7 && (t14 = [q7[2], q7[3]]);
      }
    }
    var H8 = Rt4(t14, n11, o11.arrowShapes[d10].spacing(e19) + p9), K5 = Rt4(t14, n11, o11.arrowShapes[d10].gap(e19) + p9);
    if (v11.endX = K5[0], v11.endY = K5[1], v11.arrowEndX = H8[0], v11.arrowEndY = H8[1], "inside-to-node" === D7)
      t14 = [u9.x, u9.y];
    else if (S7.units)
      t14 = this.manualEndptToPx(s10, S7);
    else if ("outside-to-line" === D7)
      t14 = v11.srcIntn;
    else if ("outside-to-node" === D7 || "outside-to-node-or-label" === D7 ? i9 = r8 : "outside-to-line" !== D7 && "outside-to-line-or-label" !== D7 || (i9 = [c9.x, c9.y]), t14 = o11.nodeShapes[this.getNodeShape(s10)].intersectLine(u9.x, u9.y, s10.outerWidth(), s10.outerHeight(), i9[0], i9[1], 0), "outside-to-node-or-label" === D7 || "outside-to-line-or-label" === D7) {
      var G5 = s10._private.rscratch, U6 = G5.labelWidth, Z5 = G5.labelHeight, $6 = G5.labelX, Q5 = G5.labelY, J5 = U6 / 2, ee2 = Z5 / 2, te2 = s10.pstyle("text-valign").value;
      "top" === te2 ? Q5 -= ee2 : "bottom" === te2 && (Q5 += ee2);
      var ne2 = s10.pstyle("text-halign").value;
      "left" === ne2 ? $6 -= J5 : "right" === ne2 && ($6 += J5);
      var re2 = Ot4(i9[0], i9[1], [$6 - J5, Q5 - ee2, $6 + J5, Q5 - ee2, $6 + J5, Q5 + ee2, $6 - J5, Q5 + ee2], u9.x, u9.y);
      if (re2.length > 0) {
        var ae2 = c9, ie2 = dt4(ae2, ot4(t14)), oe2 = dt4(ae2, ot4(re2)), se2 = ie2;
        if (oe2 < ie2 && (t14 = [re2[0], re2[1]], se2 = oe2), re2.length > 2)
          dt4(ae2, { x: re2[2], y: re2[3] }) < se2 && (t14 = [re2[2], re2[3]]);
      }
    }
    var le2 = Rt4(t14, r8, o11.arrowShapes[h9].spacing(e19) + f10), ue2 = Rt4(t14, r8, o11.arrowShapes[h9].gap(e19) + f10);
    v11.startX = ue2[0], v11.startY = ue2[1], v11.arrowStartX = le2[0], v11.arrowStartY = le2[1], k9 && (I6(v11.startX) && I6(v11.startY) && I6(v11.endX) && I6(v11.endY) ? v11.badLine = false : v11.badLine = true);
  }, getSourceEndpoint: function(e19) {
    var t14 = e19[0]._private.rscratch;
    return this.recalculateRenderedStyle(e19), "haystack" === t14.edgeType ? { x: t14.haystackPts[0], y: t14.haystackPts[1] } : { x: t14.arrowStartX, y: t14.arrowStartY };
  }, getTargetEndpoint: function(e19) {
    var t14 = e19[0]._private.rscratch;
    return this.recalculateRenderedStyle(e19), "haystack" === t14.edgeType ? { x: t14.haystackPts[2], y: t14.haystackPts[3] } : { x: t14.arrowEndX, y: t14.arrowEndY };
  } };
  var os = {};
  function ss(e19, t14, n11) {
    for (var r8 = function(e20, t15, n12, r9) {
      return pt4(e20, t15, n12, r9);
    }, a8 = t14._private.rstyle.bezierPts, i9 = 0; i9 < e19.bezierProjPcts.length; i9++) {
      var o11 = e19.bezierProjPcts[i9];
      a8.push({ x: r8(n11[0], n11[2], n11[4], o11), y: r8(n11[1], n11[3], n11[5], o11) });
    }
  }
  os.storeEdgeProjections = function(e19) {
    var t14 = e19._private, n11 = t14.rscratch, r8 = n11.edgeType;
    if (t14.rstyle.bezierPts = null, t14.rstyle.linePts = null, t14.rstyle.haystackPts = null, "multibezier" === r8 || "bezier" === r8 || "self" === r8 || "compound" === r8) {
      t14.rstyle.bezierPts = [];
      for (var a8 = 0; a8 + 5 < n11.allpts.length; a8 += 4)
        ss(this, e19, n11.allpts.slice(a8, a8 + 6));
    } else if ("segments" === r8) {
      var i9 = t14.rstyle.linePts = [];
      for (a8 = 0; a8 + 1 < n11.allpts.length; a8 += 2)
        i9.push({ x: n11.allpts[a8], y: n11.allpts[a8 + 1] });
    } else if ("haystack" === r8) {
      var o11 = n11.haystackPts;
      t14.rstyle.haystackPts = [{ x: o11[0], y: o11[1] }, { x: o11[2], y: o11[3] }];
    }
    t14.rstyle.arrowWidth = this.getArrowWidth(e19.pstyle("width").pfValue, e19.pstyle("arrow-scale").value) * this.arrowShapeWidth;
  }, os.recalculateEdgeProjections = function(e19) {
    this.findEdgeControlPoints(e19);
  };
  var ls = { recalculateNodeLabelProjection: function(e19) {
    var t14 = e19.pstyle("label").strValue;
    if (!F5(t14)) {
      var n11, r8, a8 = e19._private, i9 = e19.width(), o11 = e19.height(), s10 = e19.padding(), l10 = e19.position(), u9 = e19.pstyle("text-halign").strValue, c9 = e19.pstyle("text-valign").strValue, d10 = a8.rscratch, h9 = a8.rstyle;
      switch (u9) {
        case "left":
          n11 = l10.x - i9 / 2 - s10;
          break;
        case "right":
          n11 = l10.x + i9 / 2 + s10;
          break;
        default:
          n11 = l10.x;
      }
      switch (c9) {
        case "top":
          r8 = l10.y - o11 / 2 - s10;
          break;
        case "bottom":
          r8 = l10.y + o11 / 2 + s10;
          break;
        default:
          r8 = l10.y;
      }
      d10.labelX = n11, d10.labelY = r8, h9.labelX = n11, h9.labelY = r8, this.calculateLabelAngles(e19), this.applyLabelDimensions(e19);
    }
  } };
  var us = function(e19, t14) {
    var n11 = Math.atan(t14 / e19);
    return 0 === e19 && n11 < 0 && (n11 *= -1), n11;
  };
  var cs = function(e19, t14) {
    var n11 = t14.x - e19.x, r8 = t14.y - e19.y;
    return us(n11, r8);
  };
  ls.recalculateEdgeLabelProjections = function(e19) {
    var t14, n11 = e19._private, r8 = n11.rscratch, a8 = this, i9 = { mid: e19.pstyle("label").strValue, source: e19.pstyle("source-label").strValue, target: e19.pstyle("target-label").strValue };
    if (i9.mid || i9.source || i9.target) {
      t14 = { x: r8.midX, y: r8.midY };
      var o11 = function(e20, t15, r9) {
        Re(n11.rscratch, e20, t15, r9), Re(n11.rstyle, e20, t15, r9);
      };
      o11("labelX", null, t14.x), o11("labelY", null, t14.y);
      var s10 = us(r8.midDispX, r8.midDispY);
      o11("labelAutoAngle", null, s10);
      var l10 = function e20() {
        if (e20.cache)
          return e20.cache;
        for (var t15 = [], i10 = 0; i10 + 5 < r8.allpts.length; i10 += 4) {
          var o12 = { x: r8.allpts[i10], y: r8.allpts[i10 + 1] }, s11 = { x: r8.allpts[i10 + 2], y: r8.allpts[i10 + 3] }, l11 = { x: r8.allpts[i10 + 4], y: r8.allpts[i10 + 5] };
          t15.push({ p0: o12, p1: s11, p2: l11, startDist: 0, length: 0, segments: [] });
        }
        var u10 = n11.rstyle.bezierPts, c9 = a8.bezierProjPcts.length;
        function d10(e21, t16, n12, r9, a9) {
          var i11 = ct4(t16, n12), o13 = e21.segments[e21.segments.length - 1], s12 = { p0: t16, p1: n12, t0: r9, t1: a9, startDist: o13 ? o13.startDist + o13.length : 0, length: i11 };
          e21.segments.push(s12), e21.length += i11;
        }
        for (var h9 = 0; h9 < t15.length; h9++) {
          var p9 = t15[h9], f10 = t15[h9 - 1];
          f10 && (p9.startDist = f10.startDist + f10.length), d10(p9, p9.p0, u10[h9 * c9], 0, a8.bezierProjPcts[0]);
          for (var g8 = 0; g8 < c9 - 1; g8++)
            d10(p9, u10[h9 * c9 + g8], u10[h9 * c9 + g8 + 1], a8.bezierProjPcts[g8], a8.bezierProjPcts[g8 + 1]);
          d10(p9, u10[h9 * c9 + c9 - 1], p9.p2, a8.bezierProjPcts[c9 - 1], 1);
        }
        return e20.cache = t15;
      }, u9 = function(n12) {
        var a9, s11 = "source" === n12;
        if (i9[n12]) {
          var u10 = e19.pstyle(n12 + "-text-offset").pfValue;
          switch (r8.edgeType) {
            case "self":
            case "compound":
            case "bezier":
            case "multibezier":
              for (var c9, d10 = l10(), h9 = 0, p9 = 0, f10 = 0; f10 < d10.length; f10++) {
                for (var g8 = d10[s11 ? f10 : d10.length - 1 - f10], v11 = 0; v11 < g8.segments.length; v11++) {
                  var y9 = g8.segments[s11 ? v11 : g8.segments.length - 1 - v11], m11 = f10 === d10.length - 1 && v11 === g8.segments.length - 1;
                  if (h9 = p9, (p9 += y9.length) >= u10 || m11) {
                    c9 = { cp: g8, segment: y9 };
                    break;
                  }
                }
                if (c9)
                  break;
              }
              var b10 = c9.cp, x10 = c9.segment, w9 = (u10 - h9) / x10.length, E8 = x10.t1 - x10.t0, k9 = s11 ? x10.t0 + E8 * w9 : x10.t1 - E8 * w9;
              k9 = gt4(0, k9, 1), t14 = ft4(b10.p0, b10.p1, b10.p2, k9), a9 = function(e20, t15, n13, r9) {
                var a10 = gt4(0, r9 - 1e-3, 1), i10 = gt4(0, r9 + 1e-3, 1), o12 = ft4(e20, t15, n13, a10), s12 = ft4(e20, t15, n13, i10);
                return cs(o12, s12);
              }(b10.p0, b10.p1, b10.p2, k9);
              break;
            case "straight":
            case "segments":
            case "haystack":
              for (var C8, S7, D7, P9, T8 = 0, M8 = r8.allpts.length, B8 = 0; B8 + 3 < M8 && (s11 ? (D7 = { x: r8.allpts[B8], y: r8.allpts[B8 + 1] }, P9 = { x: r8.allpts[B8 + 2], y: r8.allpts[B8 + 3] }) : (D7 = { x: r8.allpts[M8 - 2 - B8], y: r8.allpts[M8 - 1 - B8] }, P9 = { x: r8.allpts[M8 - 4 - B8], y: r8.allpts[M8 - 3 - B8] }), S7 = T8, !((T8 += C8 = ct4(D7, P9)) >= u10)); B8 += 2)
                ;
              var _6 = (u10 - S7) / C8;
              _6 = gt4(0, _6, 1), t14 = function(e20, t15, n13, r9) {
                var a10 = t15.x - e20.x, i10 = t15.y - e20.y, o12 = ct4(e20, t15), s12 = a10 / o12, l11 = i10 / o12;
                return n13 = null == n13 ? 0 : n13, r9 = null != r9 ? r9 : n13 * o12, { x: e20.x + s12 * r9, y: e20.y + l11 * r9 };
              }(D7, P9, _6), a9 = cs(D7, P9);
          }
          o11("labelX", n12, t14.x), o11("labelY", n12, t14.y), o11("labelAutoAngle", n12, a9);
        }
      };
      u9("source"), u9("target"), this.applyLabelDimensions(e19);
    }
  }, ls.applyLabelDimensions = function(e19) {
    this.applyPrefixedLabelDimensions(e19), e19.isEdge() && (this.applyPrefixedLabelDimensions(e19, "source"), this.applyPrefixedLabelDimensions(e19, "target"));
  }, ls.applyPrefixedLabelDimensions = function(e19, t14) {
    var n11 = e19._private, r8 = this.getLabelText(e19, t14), a8 = this.calculateLabelDimensions(e19, r8), i9 = e19.pstyle("line-height").pfValue, o11 = e19.pstyle("text-wrap").strValue, s10 = Oe(n11.rscratch, "labelWrapCachedLines", t14) || [], l10 = "wrap" !== o11 ? 1 : Math.max(s10.length, 1), u9 = a8.height / l10, c9 = u9 * i9, d10 = a8.width, h9 = a8.height + (l10 - 1) * (i9 - 1) * u9;
    Re(n11.rstyle, "labelWidth", t14, d10), Re(n11.rscratch, "labelWidth", t14, d10), Re(n11.rstyle, "labelHeight", t14, h9), Re(n11.rscratch, "labelHeight", t14, h9), Re(n11.rscratch, "labelLineHeight", t14, c9);
  }, ls.getLabelText = function(e19, t14) {
    var n11 = e19._private, r8 = t14 ? t14 + "-" : "", a8 = e19.pstyle(r8 + "label").strValue, i9 = e19.pstyle("text-transform").value, o11 = function(e20, r9) {
      return r9 ? (Re(n11.rscratch, e20, t14, r9), r9) : Oe(n11.rscratch, e20, t14);
    };
    if (!a8)
      return "";
    "none" == i9 || ("uppercase" == i9 ? a8 = a8.toUpperCase() : "lowercase" == i9 && (a8 = a8.toLowerCase()));
    var s10 = e19.pstyle("text-wrap").value;
    if ("wrap" === s10) {
      var l10 = o11("labelKey");
      if (null != l10 && o11("labelWrapKey") === l10)
        return o11("labelWrapCachedText");
      for (var u9 = a8.split("\n"), c9 = e19.pstyle("text-max-width").pfValue, d10 = "anywhere" === e19.pstyle("text-overflow-wrap").value, h9 = [], p9 = /[\s\u200b]+/, f10 = d10 ? "" : " ", g8 = 0; g8 < u9.length; g8++) {
        var v11 = u9[g8], y9 = this.calculateLabelDimensions(e19, v11).width;
        if (d10) {
          var m11 = v11.split("").join("\u200B");
          v11 = m11;
        }
        if (y9 > c9) {
          for (var b10 = v11.split(p9), x10 = "", w9 = 0; w9 < b10.length; w9++) {
            var E8 = b10[w9], k9 = 0 === x10.length ? E8 : x10 + f10 + E8;
            this.calculateLabelDimensions(e19, k9).width <= c9 ? x10 += E8 + f10 : (x10 && h9.push(x10), x10 = E8 + f10);
          }
          x10.match(/^[\s\u200b]+$/) || h9.push(x10);
        } else
          h9.push(v11);
      }
      o11("labelWrapCachedLines", h9), a8 = o11("labelWrapCachedText", h9.join("\n")), o11("labelWrapKey", l10);
    } else if ("ellipsis" === s10) {
      var C8 = e19.pstyle("text-max-width").pfValue, S7 = "", D7 = false;
      if (this.calculateLabelDimensions(e19, a8).width < C8)
        return a8;
      for (var P9 = 0; P9 < a8.length; P9++) {
        if (this.calculateLabelDimensions(e19, S7 + a8[P9] + "\u2026").width > C8)
          break;
        S7 += a8[P9], P9 === a8.length - 1 && (D7 = true);
      }
      return D7 || (S7 += "\u2026"), S7;
    }
    return a8;
  }, ls.getLabelJustification = function(e19) {
    var t14 = e19.pstyle("text-justification").strValue, n11 = e19.pstyle("text-halign").strValue;
    if ("auto" !== t14)
      return t14;
    if (!e19.isNode())
      return "center";
    switch (n11) {
      case "left":
        return "right";
      case "right":
        return "left";
      default:
        return "center";
    }
  }, ls.calculateLabelDimensions = function(e19, t14) {
    var n11 = ve(t14, e19._private.labelDimsKey), r8 = this.labelDimCache || (this.labelDimCache = []), a8 = r8[n11];
    if (null != a8)
      return a8;
    var i9 = e19.pstyle("font-style").strValue, o11 = e19.pstyle("font-size").pfValue, s10 = e19.pstyle("font-family").strValue, l10 = e19.pstyle("font-weight").strValue, u9 = this.labelCalcCanvas, c9 = this.labelCalcCanvasContext;
    if (!u9) {
      u9 = this.labelCalcCanvas = document.createElement("canvas"), c9 = this.labelCalcCanvasContext = u9.getContext("2d");
      var d10 = u9.style;
      d10.position = "absolute", d10.left = "-9999px", d10.top = "-9999px", d10.zIndex = "-1", d10.visibility = "hidden", d10.pointerEvents = "none";
    }
    c9.font = "".concat(i9, " ").concat(l10, " ").concat(o11, "px ").concat(s10);
    for (var h9 = 0, p9 = 0, f10 = t14.split("\n"), g8 = 0; g8 < f10.length; g8++) {
      var v11 = f10[g8], y9 = c9.measureText(v11), m11 = Math.ceil(y9.width), b10 = o11;
      h9 = Math.max(m11, h9), p9 += b10;
    }
    return h9 += 0, p9 += 0, r8[n11] = { width: h9, height: p9 };
  }, ls.calculateLabelAngle = function(e19, t14) {
    var n11 = e19._private.rscratch, r8 = e19.isEdge(), a8 = t14 ? t14 + "-" : "", i9 = e19.pstyle(a8 + "text-rotation"), o11 = i9.strValue;
    return "none" === o11 ? 0 : r8 && "autorotate" === o11 ? n11.labelAutoAngle : "autorotate" === o11 ? 0 : i9.pfValue;
  }, ls.calculateLabelAngles = function(e19) {
    var t14 = this, n11 = e19.isEdge(), r8 = e19._private.rscratch;
    r8.labelAngle = t14.calculateLabelAngle(e19), n11 && (r8.sourceLabelAngle = t14.calculateLabelAngle(e19, "source"), r8.targetLabelAngle = t14.calculateLabelAngle(e19, "target"));
  };
  var ds = {};
  var hs = false;
  ds.getNodeShape = function(e19) {
    var t14 = e19.pstyle("shape").value;
    if ("cutrectangle" === t14 && (e19.width() < 28 || e19.height() < 28))
      return hs || (Me("The `cutrectangle` node shape can not be used at small sizes so `rectangle` is used instead"), hs = true), "rectangle";
    if (e19.isParent())
      return "rectangle" === t14 || "roundrectangle" === t14 || "round-rectangle" === t14 || "cutrectangle" === t14 || "cut-rectangle" === t14 || "barrel" === t14 ? t14 : "rectangle";
    if ("polygon" === t14) {
      var n11 = e19.pstyle("shape-polygon-points").value;
      return this.nodeShapes.makePolygon(n11).name;
    }
    return t14;
  };
  var ps = { registerCalculationListeners: function() {
    var e19 = this.cy, t14 = e19.collection(), n11 = this, r8 = function(e20) {
      var n12 = !(arguments.length > 1 && void 0 !== arguments[1]) || arguments[1];
      if (t14.merge(e20), n12)
        for (var r9 = 0; r9 < e20.length; r9++) {
          var a9 = e20[r9]._private.rstyle;
          a9.clean = false, a9.cleanConnected = false;
        }
    };
    n11.binder(e19).on("bounds.* dirty.*", function(e20) {
      var t15 = e20.target;
      r8(t15);
    }).on("style.* background.*", function(e20) {
      var t15 = e20.target;
      r8(t15, false);
    });
    var a8 = function(a9) {
      if (a9) {
        var i9 = n11.onUpdateEleCalcsFns;
        t14.cleanStyle();
        for (var o11 = 0; o11 < t14.length; o11++) {
          var s10 = t14[o11], l10 = s10._private.rstyle;
          s10.isNode() && !l10.cleanConnected && (r8(s10.connectedEdges()), l10.cleanConnected = true);
        }
        if (i9)
          for (var u9 = 0; u9 < i9.length; u9++) {
            (0, i9[u9])(a9, t14);
          }
        n11.recalculateRenderedStyle(t14), t14 = e19.collection();
      }
    };
    n11.flushRenderedStyleQueue = function() {
      a8(true);
    }, n11.beforeRender(a8, n11.beforeRenderPriorities.eleCalcs);
  }, onUpdateEleCalcs: function(e19) {
    (this.onUpdateEleCalcsFns = this.onUpdateEleCalcsFns || []).push(e19);
  }, recalculateRenderedStyle: function(e19, t14) {
    var n11 = function(e20) {
      return e20._private.rstyle.cleanConnected;
    }, r8 = [], a8 = [];
    if (!this.destroyed) {
      void 0 === t14 && (t14 = true);
      for (var i9 = 0; i9 < e19.length; i9++) {
        var o11 = e19[i9], s10 = o11._private, l10 = s10.rstyle;
        !o11.isEdge() || n11(o11.source()) && n11(o11.target()) || (l10.clean = false), t14 && l10.clean || o11.removed() || "none" !== o11.pstyle("display").value && ("nodes" === s10.group ? a8.push(o11) : r8.push(o11), l10.clean = true);
      }
      for (var u9 = 0; u9 < a8.length; u9++) {
        var c9 = a8[u9], d10 = c9._private.rstyle, h9 = c9.position();
        this.recalculateNodeLabelProjection(c9), d10.nodeX = h9.x, d10.nodeY = h9.y, d10.nodeW = c9.pstyle("width").pfValue, d10.nodeH = c9.pstyle("height").pfValue;
      }
      this.recalculateEdgeProjections(r8);
      for (var p9 = 0; p9 < r8.length; p9++) {
        var f10 = r8[p9]._private, g8 = f10.rstyle, v11 = f10.rscratch;
        g8.srcX = v11.arrowStartX, g8.srcY = v11.arrowStartY, g8.tgtX = v11.arrowEndX, g8.tgtY = v11.arrowEndY, g8.midX = v11.midX, g8.midY = v11.midY, g8.labelAngle = v11.labelAngle, g8.sourceLabelAngle = v11.sourceLabelAngle, g8.targetLabelAngle = v11.targetLabelAngle;
      }
    }
  } };
  var fs = { updateCachedGrabbedEles: function() {
    var e19 = this.cachedZSortedEles;
    if (e19) {
      e19.drag = [], e19.nondrag = [];
      for (var t14 = [], n11 = 0; n11 < e19.length; n11++) {
        var r8 = (a8 = e19[n11])._private.rscratch;
        a8.grabbed() && !a8.isParent() ? t14.push(a8) : r8.inDragLayer ? e19.drag.push(a8) : e19.nondrag.push(a8);
      }
      for (n11 = 0; n11 < t14.length; n11++) {
        var a8 = t14[n11];
        e19.drag.push(a8);
      }
    }
  }, invalidateCachedZSortedEles: function() {
    this.cachedZSortedEles = null;
  }, getCachedZSortedEles: function(e19) {
    if (e19 || !this.cachedZSortedEles) {
      var t14 = this.cy.mutableElements().toArray();
      t14.sort(Qa), t14.interactive = t14.filter(function(e20) {
        return e20.interactive();
      }), this.cachedZSortedEles = t14, this.updateCachedGrabbedEles();
    } else
      t14 = this.cachedZSortedEles;
    return t14;
  } };
  var gs = {};
  [ts, ns, rs, is, os, ls, ds, ps, fs].forEach(function(e19) {
    J4(gs, e19);
  });
  var vs = { getCachedImage: function(e19, t14, n11) {
    var r8 = this.imageCache = this.imageCache || {}, a8 = r8[e19];
    if (a8)
      return a8.image.complete || a8.image.addEventListener("load", n11), a8.image;
    var i9 = (a8 = r8[e19] = r8[e19] || {}).image = new Image();
    i9.addEventListener("load", n11), i9.addEventListener("error", function() {
      i9.error = true;
    });
    var o11 = "data:";
    return e19.substring(0, 5).toLowerCase() === o11 || (t14 = "null" === t14 ? null : t14, i9.crossOrigin = t14), i9.src = e19, i9;
  } };
  var ys = { registerBinding: function(e19, t14, n11, r8) {
    var a8 = Array.prototype.slice.apply(arguments, [1]), i9 = this.binder(e19);
    return i9.on.apply(i9, a8);
  } };
  ys.binder = function(e19) {
    var t14, n11 = this, r8 = n11.cy.window(), a8 = e19 === r8 || e19 === r8.document || e19 === r8.document.body || (t14 = e19, "undefined" != typeof HTMLElement && t14 instanceof HTMLElement);
    if (null == n11.supportsPassiveEvents) {
      var i9 = false;
      try {
        var o11 = Object.defineProperty({}, "passive", { get: function() {
          return i9 = true, true;
        } });
        r8.addEventListener("test", null, o11);
      } catch (e20) {
      }
      n11.supportsPassiveEvents = i9;
    }
    var s10 = function(t15, r9, i10) {
      var o12 = Array.prototype.slice.call(arguments);
      return a8 && n11.supportsPassiveEvents && (o12[2] = { capture: null != i10 && i10, passive: false, once: false }), n11.bindings.push({ target: e19, args: o12 }), (e19.addEventListener || e19.on).apply(e19, o12), this;
    };
    return { on: s10, addEventListener: s10, addListener: s10, bind: s10 };
  }, ys.nodeIsDraggable = function(e19) {
    return e19 && e19.isNode() && !e19.locked() && e19.grabbable();
  }, ys.nodeIsGrabbable = function(e19) {
    return this.nodeIsDraggable(e19) && e19.interactive();
  }, ys.load = function() {
    var e19 = this, t14 = e19.cy.window(), n11 = function(e20) {
      return e20.selected();
    }, r8 = function(t15, n12, r9, a9) {
      null == t15 && (t15 = e19.cy);
      for (var i10 = 0; i10 < n12.length; i10++) {
        var o12 = n12[i10];
        t15.emit({ originalEvent: r9, type: o12, position: a9 });
      }
    }, a8 = function(e20) {
      return e20.shiftKey || e20.metaKey || e20.ctrlKey;
    }, i9 = function(t15, n12) {
      var r9 = true;
      if (e19.cy.hasCompoundNodes() && t15 && t15.pannable())
        for (var a9 = 0; n12 && a9 < n12.length; a9++) {
          if ((t15 = n12[a9]).isNode() && t15.isParent() && !t15.pannable()) {
            r9 = false;
            break;
          }
        }
      else
        r9 = true;
      return r9;
    }, o11 = function(e20) {
      e20[0]._private.rscratch.inDragLayer = true;
    }, s10 = function(e20) {
      e20[0]._private.rscratch.isGrabTarget = true;
    }, l10 = function(e20, t15) {
      var n12 = t15.addToList;
      n12.has(e20) || !e20.grabbable() || e20.locked() || (n12.merge(e20), function(e21) {
        e21[0]._private.grabbed = true;
      }(e20));
    }, u9 = function(t15, n12) {
      n12 = n12 || {};
      var r9 = t15.cy().hasCompoundNodes();
      n12.inDragLayer && (t15.forEach(o11), t15.neighborhood().stdFilter(function(e20) {
        return !r9 || e20.isEdge();
      }).forEach(o11)), n12.addToList && t15.forEach(function(e20) {
        l10(e20, n12);
      }), function(e20, t16) {
        if (e20.cy().hasCompoundNodes() && (null != t16.inDragLayer || null != t16.addToList)) {
          var n13 = e20.descendants();
          t16.inDragLayer && (n13.forEach(o11), n13.connectedEdges().forEach(o11)), t16.addToList && l10(n13, t16);
        }
      }(t15, n12), p9(t15, { inDragLayer: n12.inDragLayer }), e19.updateCachedGrabbedEles();
    }, d10 = u9, h9 = function(t15) {
      t15 && (e19.getCachedZSortedEles().forEach(function(e20) {
        !function(e21) {
          e21[0]._private.grabbed = false;
        }(e20), function(e21) {
          e21[0]._private.rscratch.inDragLayer = false;
        }(e20), function(e21) {
          e21[0]._private.rscratch.isGrabTarget = false;
        }(e20);
      }), e19.updateCachedGrabbedEles());
    }, p9 = function(e20, t15) {
      if ((null != t15.inDragLayer || null != t15.addToList) && e20.cy().hasCompoundNodes()) {
        var n12 = e20.ancestors().orphans();
        if (!n12.same(e20)) {
          var r9 = n12.descendants().spawnSelf().merge(n12).unmerge(e20).unmerge(e20.descendants()), a9 = r9.connectedEdges();
          t15.inDragLayer && (a9.forEach(o11), r9.forEach(o11)), t15.addToList && r9.forEach(function(e21) {
            l10(e21, t15);
          });
        }
      }
    }, f10 = function() {
      null != document.activeElement && null != document.activeElement.blur && document.activeElement.blur();
    }, g8 = "undefined" != typeof MutationObserver, v11 = "undefined" != typeof ResizeObserver;
    g8 ? (e19.removeObserver = new MutationObserver(function(t15) {
      for (var n12 = 0; n12 < t15.length; n12++) {
        var r9 = t15[n12].removedNodes;
        if (r9)
          for (var a9 = 0; a9 < r9.length; a9++) {
            if (r9[a9] === e19.container) {
              e19.destroy();
              break;
            }
          }
      }
    }), e19.container.parentNode && e19.removeObserver.observe(e19.container.parentNode, { childList: true })) : e19.registerBinding(e19.container, "DOMNodeRemoved", function(t15) {
      e19.destroy();
    });
    var y9 = c6.default(function() {
      e19.cy.resize();
    }, 100);
    g8 && (e19.styleObserver = new MutationObserver(y9), e19.styleObserver.observe(e19.container, { attributes: true })), e19.registerBinding(t14, "resize", y9), v11 && (e19.resizeObserver = new ResizeObserver(y9), e19.resizeObserver.observe(e19.container));
    var m11 = function() {
      e19.invalidateContainerClientCoordsCache();
    };
    !function(e20, t15) {
      for (; null != e20; )
        t15(e20), e20 = e20.parentNode;
    }(e19.container, function(t15) {
      e19.registerBinding(t15, "transitionend", m11), e19.registerBinding(t15, "animationend", m11), e19.registerBinding(t15, "scroll", m11);
    }), e19.registerBinding(e19.container, "contextmenu", function(e20) {
      e20.preventDefault();
    });
    var b10, x10, w9, E8 = function(t15) {
      for (var n12 = e19.findContainerClientCoords(), r9 = n12[0], a9 = n12[1], i10 = n12[2], o12 = n12[3], s11 = t15.touches ? t15.touches : [t15], l11 = false, u10 = 0; u10 < s11.length; u10++) {
        var c9 = s11[u10];
        if (r9 <= c9.clientX && c9.clientX <= r9 + i10 && a9 <= c9.clientY && c9.clientY <= a9 + o12) {
          l11 = true;
          break;
        }
      }
      if (!l11)
        return false;
      for (var d11 = e19.container, h10 = t15.target.parentNode, p10 = false; h10; ) {
        if (h10 === d11) {
          p10 = true;
          break;
        }
        h10 = h10.parentNode;
      }
      return !!p10;
    };
    e19.registerBinding(e19.container, "mousedown", function(t15) {
      if (E8(t15)) {
        t15.preventDefault(), f10(), e19.hoverData.capture = true, e19.hoverData.which = t15.which;
        var n12 = e19.cy, a9 = [t15.clientX, t15.clientY], i10 = e19.projectIntoViewport(a9[0], a9[1]), o12 = e19.selection, l11 = e19.findNearestElements(i10[0], i10[1], true, false), c9 = l11[0], h10 = e19.dragData.possibleDragElements;
        e19.hoverData.mdownPos = i10, e19.hoverData.mdownGPos = a9;
        if (3 == t15.which) {
          e19.hoverData.cxtStarted = true;
          var p10 = { originalEvent: t15, type: "cxttapstart", position: { x: i10[0], y: i10[1] } };
          c9 ? (c9.activate(), c9.emit(p10), e19.hoverData.down = c9) : n12.emit(p10), e19.hoverData.downTime = (/* @__PURE__ */ new Date()).getTime(), e19.hoverData.cxtDragged = false;
        } else if (1 == t15.which) {
          if (c9 && c9.activate(), null != c9 && e19.nodeIsGrabbable(c9)) {
            var g9 = function(e20) {
              return { originalEvent: t15, type: e20, position: { x: i10[0], y: i10[1] } };
            };
            if (s10(c9), c9.selected()) {
              h10 = e19.dragData.possibleDragElements = n12.collection();
              var v12 = n12.$(function(t16) {
                return t16.isNode() && t16.selected() && e19.nodeIsGrabbable(t16);
              });
              u9(v12, { addToList: h10 }), c9.emit(g9("grabon")), v12.forEach(function(e20) {
                e20.emit(g9("grab"));
              });
            } else
              h10 = e19.dragData.possibleDragElements = n12.collection(), d10(c9, { addToList: h10 }), c9.emit(g9("grabon")).emit(g9("grab"));
            e19.redrawHint("eles", true), e19.redrawHint("drag", true);
          }
          e19.hoverData.down = c9, e19.hoverData.downs = l11, e19.hoverData.downTime = (/* @__PURE__ */ new Date()).getTime(), r8(c9, ["mousedown", "tapstart", "vmousedown"], t15, { x: i10[0], y: i10[1] }), null == c9 ? (o12[4] = 1, e19.data.bgActivePosistion = { x: i10[0], y: i10[1] }, e19.redrawHint("select", true), e19.redraw()) : c9.pannable() && (o12[4] = 1), e19.hoverData.tapholdCancelled = false, clearTimeout(e19.hoverData.tapholdTimeout), e19.hoverData.tapholdTimeout = setTimeout(function() {
            if (!e19.hoverData.tapholdCancelled) {
              var r9 = e19.hoverData.down;
              r9 ? r9.emit({ originalEvent: t15, type: "taphold", position: { x: i10[0], y: i10[1] } }) : n12.emit({ originalEvent: t15, type: "taphold", position: { x: i10[0], y: i10[1] } });
            }
          }, e19.tapholdDuration);
        }
        o12[0] = o12[2] = i10[0], o12[1] = o12[3] = i10[1];
      }
    }, false), e19.registerBinding(t14, "mousemove", function(t15) {
      if (e19.hoverData.capture || E8(t15)) {
        var n12 = false, o12 = e19.cy, s11 = o12.zoom(), l11 = [t15.clientX, t15.clientY], c9 = e19.projectIntoViewport(l11[0], l11[1]), d11 = e19.hoverData.mdownPos, p10 = e19.hoverData.mdownGPos, f11 = e19.selection, g9 = null;
        e19.hoverData.draggingEles || e19.hoverData.dragging || e19.hoverData.selecting || (g9 = e19.findNearestElement(c9[0], c9[1], true, false));
        var v12, y10 = e19.hoverData.last, m12 = e19.hoverData.down, b11 = [c9[0] - f11[2], c9[1] - f11[3]], x11 = e19.dragData.possibleDragElements;
        if (p10) {
          var w10 = l11[0] - p10[0], k10 = w10 * w10, C9 = l11[1] - p10[1], S8 = k10 + C9 * C9;
          e19.hoverData.isOverThresholdDrag = v12 = S8 >= e19.desktopTapThreshold2;
        }
        var D8 = a8(t15);
        v12 && (e19.hoverData.tapholdCancelled = true);
        n12 = true, r8(g9, ["mousemove", "vmousemove", "tapdrag"], t15, { x: c9[0], y: c9[1] });
        var P10 = function() {
          e19.data.bgActivePosistion = void 0, e19.hoverData.selecting || o12.emit({ originalEvent: t15, type: "boxstart", position: { x: c9[0], y: c9[1] } }), f11[4] = 1, e19.hoverData.selecting = true, e19.redrawHint("select", true), e19.redraw();
        };
        if (3 === e19.hoverData.which) {
          if (v12) {
            var T9 = { originalEvent: t15, type: "cxtdrag", position: { x: c9[0], y: c9[1] } };
            m12 ? m12.emit(T9) : o12.emit(T9), e19.hoverData.cxtDragged = true, e19.hoverData.cxtOver && g9 === e19.hoverData.cxtOver || (e19.hoverData.cxtOver && e19.hoverData.cxtOver.emit({ originalEvent: t15, type: "cxtdragout", position: { x: c9[0], y: c9[1] } }), e19.hoverData.cxtOver = g9, g9 && g9.emit({ originalEvent: t15, type: "cxtdragover", position: { x: c9[0], y: c9[1] } }));
          }
        } else if (e19.hoverData.dragging) {
          if (n12 = true, o12.panningEnabled() && o12.userPanningEnabled()) {
            var M9;
            if (e19.hoverData.justStartedPan) {
              var B9 = e19.hoverData.mdownPos;
              M9 = { x: (c9[0] - B9[0]) * s11, y: (c9[1] - B9[1]) * s11 }, e19.hoverData.justStartedPan = false;
            } else
              M9 = { x: b11[0] * s11, y: b11[1] * s11 };
            o12.panBy(M9), o12.emit("dragpan"), e19.hoverData.dragged = true;
          }
          c9 = e19.projectIntoViewport(t15.clientX, t15.clientY);
        } else if (1 != f11[4] || null != m12 && !m12.pannable()) {
          if (m12 && m12.pannable() && m12.active() && m12.unactivate(), m12 && m12.grabbed() || g9 == y10 || (y10 && r8(y10, ["mouseout", "tapdragout"], t15, { x: c9[0], y: c9[1] }), g9 && r8(g9, ["mouseover", "tapdragover"], t15, { x: c9[0], y: c9[1] }), e19.hoverData.last = g9), m12)
            if (v12) {
              if (o12.boxSelectionEnabled() && D8)
                m12 && m12.grabbed() && (h9(x11), m12.emit("freeon"), x11.emit("free"), e19.dragData.didDrag && (m12.emit("dragfreeon"), x11.emit("dragfree"))), P10();
              else if (m12 && m12.grabbed() && e19.nodeIsDraggable(m12)) {
                var _7 = !e19.dragData.didDrag;
                _7 && e19.redrawHint("eles", true), e19.dragData.didDrag = true, e19.hoverData.draggingEles || u9(x11, { inDragLayer: true });
                var N8 = { x: 0, y: 0 };
                if (I6(b11[0]) && I6(b11[1]) && (N8.x += b11[0], N8.y += b11[1], _7)) {
                  var z8 = e19.hoverData.dragDelta;
                  z8 && I6(z8[0]) && I6(z8[1]) && (N8.x += z8[0], N8.y += z8[1]);
                }
                e19.hoverData.draggingEles = true, x11.silentShift(N8).emit("position drag"), e19.redrawHint("drag", true), e19.redraw();
              }
            } else
              !function() {
                var t16 = e19.hoverData.dragDelta = e19.hoverData.dragDelta || [];
                0 === t16.length ? (t16.push(b11[0]), t16.push(b11[1])) : (t16[0] += b11[0], t16[1] += b11[1]);
              }();
          n12 = true;
        } else if (v12) {
          if (e19.hoverData.dragging || !o12.boxSelectionEnabled() || !D8 && o12.panningEnabled() && o12.userPanningEnabled()) {
            if (!e19.hoverData.selecting && o12.panningEnabled() && o12.userPanningEnabled()) {
              i9(m12, e19.hoverData.downs) && (e19.hoverData.dragging = true, e19.hoverData.justStartedPan = true, f11[4] = 0, e19.data.bgActivePosistion = ot4(d11), e19.redrawHint("select", true), e19.redraw());
            }
          } else
            P10();
          m12 && m12.pannable() && m12.active() && m12.unactivate();
        }
        return f11[2] = c9[0], f11[3] = c9[1], n12 ? (t15.stopPropagation && t15.stopPropagation(), t15.preventDefault && t15.preventDefault(), false) : void 0;
      }
    }, false), e19.registerBinding(t14, "mouseup", function(t15) {
      if (e19.hoverData.capture) {
        e19.hoverData.capture = false;
        var i10 = e19.cy, o12 = e19.projectIntoViewport(t15.clientX, t15.clientY), s11 = e19.selection, l11 = e19.findNearestElement(o12[0], o12[1], true, false), u10 = e19.dragData.possibleDragElements, c9 = e19.hoverData.down, d11 = a8(t15);
        if (e19.data.bgActivePosistion && (e19.redrawHint("select", true), e19.redraw()), e19.hoverData.tapholdCancelled = true, e19.data.bgActivePosistion = void 0, c9 && c9.unactivate(), 3 === e19.hoverData.which) {
          var p10 = { originalEvent: t15, type: "cxttapend", position: { x: o12[0], y: o12[1] } };
          if (c9 ? c9.emit(p10) : i10.emit(p10), !e19.hoverData.cxtDragged) {
            var f11 = { originalEvent: t15, type: "cxttap", position: { x: o12[0], y: o12[1] } };
            c9 ? c9.emit(f11) : i10.emit(f11);
          }
          e19.hoverData.cxtDragged = false, e19.hoverData.which = null;
        } else if (1 === e19.hoverData.which) {
          if (r8(l11, ["mouseup", "tapend", "vmouseup"], t15, { x: o12[0], y: o12[1] }), e19.dragData.didDrag || e19.hoverData.dragged || e19.hoverData.selecting || e19.hoverData.isOverThresholdDrag || (r8(c9, ["click", "tap", "vclick"], t15, { x: o12[0], y: o12[1] }), x10 = false, t15.timeStamp - w9 <= i10.multiClickDebounceTime() ? (b10 && clearTimeout(b10), x10 = true, w9 = null, r8(c9, ["dblclick", "dbltap", "vdblclick"], t15, { x: o12[0], y: o12[1] })) : (b10 = setTimeout(function() {
            x10 || r8(c9, ["oneclick", "onetap", "voneclick"], t15, { x: o12[0], y: o12[1] });
          }, i10.multiClickDebounceTime()), w9 = t15.timeStamp)), null != c9 || e19.dragData.didDrag || e19.hoverData.selecting || e19.hoverData.dragged || a8(t15) || (i10.$(n11).unselect(["tapunselect"]), u10.length > 0 && e19.redrawHint("eles", true), e19.dragData.possibleDragElements = u10 = i10.collection()), l11 != c9 || e19.dragData.didDrag || e19.hoverData.selecting || null != l11 && l11._private.selectable && (e19.hoverData.dragging || ("additive" === i10.selectionType() || d11 ? l11.selected() ? l11.unselect(["tapunselect"]) : l11.select(["tapselect"]) : d11 || (i10.$(n11).unmerge(l11).unselect(["tapunselect"]), l11.select(["tapselect"]))), e19.redrawHint("eles", true)), e19.hoverData.selecting) {
            var g9 = i10.collection(e19.getAllInBox(s11[0], s11[1], s11[2], s11[3]));
            e19.redrawHint("select", true), g9.length > 0 && e19.redrawHint("eles", true), i10.emit({ type: "boxend", originalEvent: t15, position: { x: o12[0], y: o12[1] } });
            var v12 = function(e20) {
              return e20.selectable() && !e20.selected();
            };
            "additive" === i10.selectionType() || d11 || i10.$(n11).unmerge(g9).unselect(), g9.emit("box").stdFilter(v12).select().emit("boxselect"), e19.redraw();
          }
          if (e19.hoverData.dragging && (e19.hoverData.dragging = false, e19.redrawHint("select", true), e19.redrawHint("eles", true), e19.redraw()), !s11[4]) {
            e19.redrawHint("drag", true), e19.redrawHint("eles", true);
            var y10 = c9 && c9.grabbed();
            h9(u10), y10 && (c9.emit("freeon"), u10.emit("free"), e19.dragData.didDrag && (c9.emit("dragfreeon"), u10.emit("dragfree")));
          }
        }
        s11[4] = 0, e19.hoverData.down = null, e19.hoverData.cxtStarted = false, e19.hoverData.draggingEles = false, e19.hoverData.selecting = false, e19.hoverData.isOverThresholdDrag = false, e19.dragData.didDrag = false, e19.hoverData.dragged = false, e19.hoverData.dragDelta = [], e19.hoverData.mdownPos = null, e19.hoverData.mdownGPos = null;
      }
    }, false);
    var k9, C8, S7, D7, P9, T8, M8, B8, _6, N7, z7, L9, A9, O8 = function(t15) {
      if (!e19.scrollingPage) {
        var n12 = e19.cy, r9 = n12.zoom(), a9 = n12.pan(), i10 = e19.projectIntoViewport(t15.clientX, t15.clientY), o12 = [i10[0] * r9 + a9.x, i10[1] * r9 + a9.y];
        if (e19.hoverData.draggingEles || e19.hoverData.dragging || e19.hoverData.cxtStarted || 0 !== e19.selection[4])
          t15.preventDefault();
        else if (n12.panningEnabled() && n12.userPanningEnabled() && n12.zoomingEnabled() && n12.userZoomingEnabled()) {
          var s11;
          t15.preventDefault(), e19.data.wheelZooming = true, clearTimeout(e19.data.wheelTimeout), e19.data.wheelTimeout = setTimeout(function() {
            e19.data.wheelZooming = false, e19.redrawHint("eles", true), e19.redraw();
          }, 150), s11 = null != t15.deltaY ? t15.deltaY / -250 : null != t15.wheelDeltaY ? t15.wheelDeltaY / 1e3 : t15.wheelDelta / 1e3, s11 *= e19.wheelSensitivity, 1 === t15.deltaMode && (s11 *= 33);
          var l11 = n12.zoom() * Math.pow(10, s11);
          "gesturechange" === t15.type && (l11 = e19.gestureStartZoom * t15.scale), n12.zoom({ level: l11, renderedPosition: { x: o12[0], y: o12[1] } }), n12.emit("gesturechange" === t15.type ? "pinchzoom" : "scrollzoom");
        }
      }
    };
    e19.registerBinding(e19.container, "wheel", O8, true), e19.registerBinding(t14, "scroll", function(t15) {
      e19.scrollingPage = true, clearTimeout(e19.scrollingPageTimeout), e19.scrollingPageTimeout = setTimeout(function() {
        e19.scrollingPage = false;
      }, 250);
    }, true), e19.registerBinding(e19.container, "gesturestart", function(t15) {
      e19.gestureStartZoom = e19.cy.zoom(), e19.hasTouchStarted || t15.preventDefault();
    }, true), e19.registerBinding(e19.container, "gesturechange", function(t15) {
      e19.hasTouchStarted || O8(t15);
    }, true), e19.registerBinding(e19.container, "mouseout", function(t15) {
      var n12 = e19.projectIntoViewport(t15.clientX, t15.clientY);
      e19.cy.emit({ originalEvent: t15, type: "mouseout", position: { x: n12[0], y: n12[1] } });
    }, false), e19.registerBinding(e19.container, "mouseover", function(t15) {
      var n12 = e19.projectIntoViewport(t15.clientX, t15.clientY);
      e19.cy.emit({ originalEvent: t15, type: "mouseover", position: { x: n12[0], y: n12[1] } });
    }, false);
    var R7, V6, F7, q7, j8, Y5, X5, W7 = function(e20, t15, n12, r9) {
      return Math.sqrt((n12 - e20) * (n12 - e20) + (r9 - t15) * (r9 - t15));
    }, H8 = function(e20, t15, n12, r9) {
      return (n12 - e20) * (n12 - e20) + (r9 - t15) * (r9 - t15);
    };
    if (e19.registerBinding(e19.container, "touchstart", R7 = function(t15) {
      if (e19.hasTouchStarted = true, E8(t15)) {
        f10(), e19.touchData.capture = true, e19.data.bgActivePosistion = void 0;
        var n12 = e19.cy, a9 = e19.touchData.now, i10 = e19.touchData.earlier;
        if (t15.touches[0]) {
          var o12 = e19.projectIntoViewport(t15.touches[0].clientX, t15.touches[0].clientY);
          a9[0] = o12[0], a9[1] = o12[1];
        }
        if (t15.touches[1]) {
          o12 = e19.projectIntoViewport(t15.touches[1].clientX, t15.touches[1].clientY);
          a9[2] = o12[0], a9[3] = o12[1];
        }
        if (t15.touches[2]) {
          o12 = e19.projectIntoViewport(t15.touches[2].clientX, t15.touches[2].clientY);
          a9[4] = o12[0], a9[5] = o12[1];
        }
        if (t15.touches[1]) {
          e19.touchData.singleTouchMoved = true, h9(e19.dragData.touchDragEles);
          var l11 = e19.findContainerClientCoords();
          _6 = l11[0], N7 = l11[1], z7 = l11[2], L9 = l11[3], k9 = t15.touches[0].clientX - _6, C8 = t15.touches[0].clientY - N7, S7 = t15.touches[1].clientX - _6, D7 = t15.touches[1].clientY - N7, A9 = 0 <= k9 && k9 <= z7 && 0 <= S7 && S7 <= z7 && 0 <= C8 && C8 <= L9 && 0 <= D7 && D7 <= L9;
          var c9 = n12.pan(), p10 = n12.zoom();
          P9 = W7(k9, C8, S7, D7), T8 = H8(k9, C8, S7, D7), B8 = [((M8 = [(k9 + S7) / 2, (C8 + D7) / 2])[0] - c9.x) / p10, (M8[1] - c9.y) / p10];
          if (T8 < 4e4 && !t15.touches[2]) {
            var g9 = e19.findNearestElement(a9[0], a9[1], true, true), v12 = e19.findNearestElement(a9[2], a9[3], true, true);
            return g9 && g9.isNode() ? (g9.activate().emit({ originalEvent: t15, type: "cxttapstart", position: { x: a9[0], y: a9[1] } }), e19.touchData.start = g9) : v12 && v12.isNode() ? (v12.activate().emit({ originalEvent: t15, type: "cxttapstart", position: { x: a9[0], y: a9[1] } }), e19.touchData.start = v12) : n12.emit({ originalEvent: t15, type: "cxttapstart", position: { x: a9[0], y: a9[1] } }), e19.touchData.start && (e19.touchData.start._private.grabbed = false), e19.touchData.cxt = true, e19.touchData.cxtDragged = false, e19.data.bgActivePosistion = void 0, void e19.redraw();
          }
        }
        if (t15.touches[2])
          n12.boxSelectionEnabled() && t15.preventDefault();
        else if (t15.touches[1])
          ;
        else if (t15.touches[0]) {
          var y10 = e19.findNearestElements(a9[0], a9[1], true, true), m12 = y10[0];
          if (null != m12 && (m12.activate(), e19.touchData.start = m12, e19.touchData.starts = y10, e19.nodeIsGrabbable(m12))) {
            var b11 = e19.dragData.touchDragEles = n12.collection(), x11 = null;
            e19.redrawHint("eles", true), e19.redrawHint("drag", true), m12.selected() ? (x11 = n12.$(function(t16) {
              return t16.selected() && e19.nodeIsGrabbable(t16);
            }), u9(x11, { addToList: b11 })) : d10(m12, { addToList: b11 }), s10(m12);
            var w10 = function(e20) {
              return { originalEvent: t15, type: e20, position: { x: a9[0], y: a9[1] } };
            };
            m12.emit(w10("grabon")), x11 ? x11.forEach(function(e20) {
              e20.emit(w10("grab"));
            }) : m12.emit(w10("grab"));
          }
          r8(m12, ["touchstart", "tapstart", "vmousedown"], t15, { x: a9[0], y: a9[1] }), null == m12 && (e19.data.bgActivePosistion = { x: o12[0], y: o12[1] }, e19.redrawHint("select", true), e19.redraw()), e19.touchData.singleTouchMoved = false, e19.touchData.singleTouchStartTime = +/* @__PURE__ */ new Date(), clearTimeout(e19.touchData.tapholdTimeout), e19.touchData.tapholdTimeout = setTimeout(function() {
            false !== e19.touchData.singleTouchMoved || e19.pinching || e19.touchData.selecting || r8(e19.touchData.start, ["taphold"], t15, { x: a9[0], y: a9[1] });
          }, e19.tapholdDuration);
        }
        if (t15.touches.length >= 1) {
          for (var I7 = e19.touchData.startPosition = [null, null, null, null, null, null], O9 = 0; O9 < a9.length; O9++)
            I7[O9] = i10[O9] = a9[O9];
          var R8 = t15.touches[0];
          e19.touchData.startGPosition = [R8.clientX, R8.clientY];
        }
      }
    }, false), e19.registerBinding(window, "touchmove", V6 = function(t15) {
      var n12 = e19.touchData.capture;
      if (n12 || E8(t15)) {
        var a9 = e19.selection, o12 = e19.cy, s11 = e19.touchData.now, l11 = e19.touchData.earlier, c9 = o12.zoom();
        if (t15.touches[0]) {
          var d11 = e19.projectIntoViewport(t15.touches[0].clientX, t15.touches[0].clientY);
          s11[0] = d11[0], s11[1] = d11[1];
        }
        if (t15.touches[1]) {
          d11 = e19.projectIntoViewport(t15.touches[1].clientX, t15.touches[1].clientY);
          s11[2] = d11[0], s11[3] = d11[1];
        }
        if (t15.touches[2]) {
          d11 = e19.projectIntoViewport(t15.touches[2].clientX, t15.touches[2].clientY);
          s11[4] = d11[0], s11[5] = d11[1];
        }
        var p10, f11 = e19.touchData.startGPosition;
        if (n12 && t15.touches[0] && f11) {
          for (var g9 = [], v12 = 0; v12 < s11.length; v12++)
            g9[v12] = s11[v12] - l11[v12];
          var y10 = t15.touches[0].clientX - f11[0], m12 = y10 * y10, b11 = t15.touches[0].clientY - f11[1];
          p10 = m12 + b11 * b11 >= e19.touchTapThreshold2;
        }
        if (n12 && e19.touchData.cxt) {
          t15.preventDefault();
          var x11 = t15.touches[0].clientX - _6, w10 = t15.touches[0].clientY - N7, M9 = t15.touches[1].clientX - _6, z8 = t15.touches[1].clientY - N7, L10 = H8(x11, w10, M9, z8);
          if (L10 / T8 >= 2.25 || L10 >= 22500) {
            e19.touchData.cxt = false, e19.data.bgActivePosistion = void 0, e19.redrawHint("select", true);
            var O9 = { originalEvent: t15, type: "cxttapend", position: { x: s11[0], y: s11[1] } };
            e19.touchData.start ? (e19.touchData.start.unactivate().emit(O9), e19.touchData.start = null) : o12.emit(O9);
          }
        }
        if (n12 && e19.touchData.cxt) {
          O9 = { originalEvent: t15, type: "cxtdrag", position: { x: s11[0], y: s11[1] } };
          e19.data.bgActivePosistion = void 0, e19.redrawHint("select", true), e19.touchData.start ? e19.touchData.start.emit(O9) : o12.emit(O9), e19.touchData.start && (e19.touchData.start._private.grabbed = false), e19.touchData.cxtDragged = true;
          var R8 = e19.findNearestElement(s11[0], s11[1], true, true);
          e19.touchData.cxtOver && R8 === e19.touchData.cxtOver || (e19.touchData.cxtOver && e19.touchData.cxtOver.emit({ originalEvent: t15, type: "cxtdragout", position: { x: s11[0], y: s11[1] } }), e19.touchData.cxtOver = R8, R8 && R8.emit({ originalEvent: t15, type: "cxtdragover", position: { x: s11[0], y: s11[1] } }));
        } else if (n12 && t15.touches[2] && o12.boxSelectionEnabled())
          t15.preventDefault(), e19.data.bgActivePosistion = void 0, this.lastThreeTouch = +/* @__PURE__ */ new Date(), e19.touchData.selecting || o12.emit({ originalEvent: t15, type: "boxstart", position: { x: s11[0], y: s11[1] } }), e19.touchData.selecting = true, e19.touchData.didSelect = true, a9[4] = 1, a9 && 0 !== a9.length && void 0 !== a9[0] ? (a9[2] = (s11[0] + s11[2] + s11[4]) / 3, a9[3] = (s11[1] + s11[3] + s11[5]) / 3) : (a9[0] = (s11[0] + s11[2] + s11[4]) / 3, a9[1] = (s11[1] + s11[3] + s11[5]) / 3, a9[2] = (s11[0] + s11[2] + s11[4]) / 3 + 1, a9[3] = (s11[1] + s11[3] + s11[5]) / 3 + 1), e19.redrawHint("select", true), e19.redraw();
        else if (n12 && t15.touches[1] && !e19.touchData.didSelect && o12.zoomingEnabled() && o12.panningEnabled() && o12.userZoomingEnabled() && o12.userPanningEnabled()) {
          if (t15.preventDefault(), e19.data.bgActivePosistion = void 0, e19.redrawHint("select", true), ee2 = e19.dragData.touchDragEles) {
            e19.redrawHint("drag", true);
            for (var V7 = 0; V7 < ee2.length; V7++) {
              var F8 = ee2[V7]._private;
              F8.grabbed = false, F8.rscratch.inDragLayer = false;
            }
          }
          var q8 = e19.touchData.start, j9 = (x11 = t15.touches[0].clientX - _6, w10 = t15.touches[0].clientY - N7, M9 = t15.touches[1].clientX - _6, z8 = t15.touches[1].clientY - N7, W7(x11, w10, M9, z8)), Y6 = j9 / P9;
          if (A9) {
            var X6 = (x11 - k9 + (M9 - S7)) / 2, K6 = (w10 - C8 + (z8 - D7)) / 2, G6 = o12.zoom(), U7 = G6 * Y6, Z6 = o12.pan(), $7 = B8[0] * G6 + Z6.x, Q6 = B8[1] * G6 + Z6.y, J5 = { x: -U7 / G6 * ($7 - Z6.x - X6) + $7, y: -U7 / G6 * (Q6 - Z6.y - K6) + Q6 };
            if (q8 && q8.active()) {
              var ee2 = e19.dragData.touchDragEles;
              h9(ee2), e19.redrawHint("drag", true), e19.redrawHint("eles", true), q8.unactivate().emit("freeon"), ee2.emit("free"), e19.dragData.didDrag && (q8.emit("dragfreeon"), ee2.emit("dragfree"));
            }
            o12.viewport({ zoom: U7, pan: J5, cancelOnFailedZoom: true }), o12.emit("pinchzoom"), P9 = j9, k9 = x11, C8 = w10, S7 = M9, D7 = z8, e19.pinching = true;
          }
          if (t15.touches[0]) {
            d11 = e19.projectIntoViewport(t15.touches[0].clientX, t15.touches[0].clientY);
            s11[0] = d11[0], s11[1] = d11[1];
          }
          if (t15.touches[1]) {
            d11 = e19.projectIntoViewport(t15.touches[1].clientX, t15.touches[1].clientY);
            s11[2] = d11[0], s11[3] = d11[1];
          }
          if (t15.touches[2]) {
            d11 = e19.projectIntoViewport(t15.touches[2].clientX, t15.touches[2].clientY);
            s11[4] = d11[0], s11[5] = d11[1];
          }
        } else if (t15.touches[0] && !e19.touchData.didSelect) {
          var te2 = e19.touchData.start, ne2 = e19.touchData.last;
          if (e19.hoverData.draggingEles || e19.swipePanning || (R8 = e19.findNearestElement(s11[0], s11[1], true, true)), n12 && null != te2 && t15.preventDefault(), n12 && null != te2 && e19.nodeIsDraggable(te2))
            if (p10) {
              ee2 = e19.dragData.touchDragEles;
              var re2 = !e19.dragData.didDrag;
              re2 && u9(ee2, { inDragLayer: true }), e19.dragData.didDrag = true;
              var ae2 = { x: 0, y: 0 };
              if (I6(g9[0]) && I6(g9[1])) {
                if (ae2.x += g9[0], ae2.y += g9[1], re2)
                  e19.redrawHint("eles", true), (ie2 = e19.touchData.dragDelta) && I6(ie2[0]) && I6(ie2[1]) && (ae2.x += ie2[0], ae2.y += ie2[1]);
              }
              e19.hoverData.draggingEles = true, ee2.silentShift(ae2).emit("position drag"), e19.redrawHint("drag", true), e19.touchData.startPosition[0] == l11[0] && e19.touchData.startPosition[1] == l11[1] && e19.redrawHint("eles", true), e19.redraw();
            } else {
              var ie2;
              0 === (ie2 = e19.touchData.dragDelta = e19.touchData.dragDelta || []).length ? (ie2.push(g9[0]), ie2.push(g9[1])) : (ie2[0] += g9[0], ie2[1] += g9[1]);
            }
          if (r8(te2 || R8, ["touchmove", "tapdrag", "vmousemove"], t15, { x: s11[0], y: s11[1] }), te2 && te2.grabbed() || R8 == ne2 || (ne2 && ne2.emit({ originalEvent: t15, type: "tapdragout", position: { x: s11[0], y: s11[1] } }), R8 && R8.emit({ originalEvent: t15, type: "tapdragover", position: { x: s11[0], y: s11[1] } })), e19.touchData.last = R8, n12)
            for (V7 = 0; V7 < s11.length; V7++)
              s11[V7] && e19.touchData.startPosition[V7] && p10 && (e19.touchData.singleTouchMoved = true);
          if (n12 && (null == te2 || te2.pannable()) && o12.panningEnabled() && o12.userPanningEnabled()) {
            i9(te2, e19.touchData.starts) && (t15.preventDefault(), e19.data.bgActivePosistion || (e19.data.bgActivePosistion = ot4(e19.touchData.startPosition)), e19.swipePanning ? (o12.panBy({ x: g9[0] * c9, y: g9[1] * c9 }), o12.emit("dragpan")) : p10 && (e19.swipePanning = true, o12.panBy({ x: y10 * c9, y: b11 * c9 }), o12.emit("dragpan"), te2 && (te2.unactivate(), e19.redrawHint("select", true), e19.touchData.start = null)));
            d11 = e19.projectIntoViewport(t15.touches[0].clientX, t15.touches[0].clientY);
            s11[0] = d11[0], s11[1] = d11[1];
          }
        }
        for (v12 = 0; v12 < s11.length; v12++)
          l11[v12] = s11[v12];
        n12 && t15.touches.length > 0 && !e19.hoverData.draggingEles && !e19.swipePanning && null != e19.data.bgActivePosistion && (e19.data.bgActivePosistion = void 0, e19.redrawHint("select", true), e19.redraw());
      }
    }, false), e19.registerBinding(t14, "touchcancel", F7 = function(t15) {
      var n12 = e19.touchData.start;
      e19.touchData.capture = false, n12 && n12.unactivate();
    }), e19.registerBinding(t14, "touchend", q7 = function(t15) {
      var a9 = e19.touchData.start;
      if (e19.touchData.capture) {
        0 === t15.touches.length && (e19.touchData.capture = false), t15.preventDefault();
        var i10 = e19.selection;
        e19.swipePanning = false, e19.hoverData.draggingEles = false;
        var o12, s11 = e19.cy, l11 = s11.zoom(), u10 = e19.touchData.now, c9 = e19.touchData.earlier;
        if (t15.touches[0]) {
          var d11 = e19.projectIntoViewport(t15.touches[0].clientX, t15.touches[0].clientY);
          u10[0] = d11[0], u10[1] = d11[1];
        }
        if (t15.touches[1]) {
          d11 = e19.projectIntoViewport(t15.touches[1].clientX, t15.touches[1].clientY);
          u10[2] = d11[0], u10[3] = d11[1];
        }
        if (t15.touches[2]) {
          d11 = e19.projectIntoViewport(t15.touches[2].clientX, t15.touches[2].clientY);
          u10[4] = d11[0], u10[5] = d11[1];
        }
        if (a9 && a9.unactivate(), e19.touchData.cxt) {
          if (o12 = { originalEvent: t15, type: "cxttapend", position: { x: u10[0], y: u10[1] } }, a9 ? a9.emit(o12) : s11.emit(o12), !e19.touchData.cxtDragged) {
            var p10 = { originalEvent: t15, type: "cxttap", position: { x: u10[0], y: u10[1] } };
            a9 ? a9.emit(p10) : s11.emit(p10);
          }
          return e19.touchData.start && (e19.touchData.start._private.grabbed = false), e19.touchData.cxt = false, e19.touchData.start = null, void e19.redraw();
        }
        if (!t15.touches[2] && s11.boxSelectionEnabled() && e19.touchData.selecting) {
          e19.touchData.selecting = false;
          var f11 = s11.collection(e19.getAllInBox(i10[0], i10[1], i10[2], i10[3]));
          i10[0] = void 0, i10[1] = void 0, i10[2] = void 0, i10[3] = void 0, i10[4] = 0, e19.redrawHint("select", true), s11.emit({ type: "boxend", originalEvent: t15, position: { x: u10[0], y: u10[1] } });
          f11.emit("box").stdFilter(function(e20) {
            return e20.selectable() && !e20.selected();
          }).select().emit("boxselect"), f11.nonempty() && e19.redrawHint("eles", true), e19.redraw();
        }
        if (null != a9 && a9.unactivate(), t15.touches[2])
          e19.data.bgActivePosistion = void 0, e19.redrawHint("select", true);
        else if (t15.touches[1])
          ;
        else if (t15.touches[0])
          ;
        else if (!t15.touches[0]) {
          e19.data.bgActivePosistion = void 0, e19.redrawHint("select", true);
          var g9 = e19.dragData.touchDragEles;
          if (null != a9) {
            var v12 = a9._private.grabbed;
            h9(g9), e19.redrawHint("drag", true), e19.redrawHint("eles", true), v12 && (a9.emit("freeon"), g9.emit("free"), e19.dragData.didDrag && (a9.emit("dragfreeon"), g9.emit("dragfree"))), r8(a9, ["touchend", "tapend", "vmouseup", "tapdragout"], t15, { x: u10[0], y: u10[1] }), a9.unactivate(), e19.touchData.start = null;
          } else {
            var y10 = e19.findNearestElement(u10[0], u10[1], true, true);
            r8(y10, ["touchend", "tapend", "vmouseup", "tapdragout"], t15, { x: u10[0], y: u10[1] });
          }
          var m12 = e19.touchData.startPosition[0] - u10[0], b11 = m12 * m12, x11 = e19.touchData.startPosition[1] - u10[1], w10 = (b11 + x11 * x11) * l11 * l11;
          e19.touchData.singleTouchMoved || (a9 || s11.$(":selected").unselect(["tapunselect"]), r8(a9, ["tap", "vclick"], t15, { x: u10[0], y: u10[1] }), j8 = false, t15.timeStamp - X5 <= s11.multiClickDebounceTime() ? (Y5 && clearTimeout(Y5), j8 = true, X5 = null, r8(a9, ["dbltap", "vdblclick"], t15, { x: u10[0], y: u10[1] })) : (Y5 = setTimeout(function() {
            j8 || r8(a9, ["onetap", "voneclick"], t15, { x: u10[0], y: u10[1] });
          }, s11.multiClickDebounceTime()), X5 = t15.timeStamp)), null != a9 && !e19.dragData.didDrag && a9._private.selectable && w10 < e19.touchTapThreshold2 && !e19.pinching && ("single" === s11.selectionType() ? (s11.$(n11).unmerge(a9).unselect(["tapunselect"]), a9.select(["tapselect"])) : a9.selected() ? a9.unselect(["tapunselect"]) : a9.select(["tapselect"]), e19.redrawHint("eles", true)), e19.touchData.singleTouchMoved = true;
        }
        for (var E9 = 0; E9 < u10.length; E9++)
          c9[E9] = u10[E9];
        e19.dragData.didDrag = false, 0 === t15.touches.length && (e19.touchData.dragDelta = [], e19.touchData.startPosition = [null, null, null, null, null, null], e19.touchData.startGPosition = null, e19.touchData.didSelect = false), t15.touches.length < 2 && (1 === t15.touches.length && (e19.touchData.startGPosition = [t15.touches[0].clientX, t15.touches[0].clientY]), e19.pinching = false, e19.redrawHint("eles", true), e19.redraw());
      }
    }, false), "undefined" == typeof TouchEvent) {
      var K5 = [], G5 = function(e20) {
        return { clientX: e20.clientX, clientY: e20.clientY, force: 1, identifier: e20.pointerId, pageX: e20.pageX, pageY: e20.pageY, radiusX: e20.width / 2, radiusY: e20.height / 2, screenX: e20.screenX, screenY: e20.screenY, target: e20.target };
      }, U6 = function(e20) {
        K5.push(function(e21) {
          return { event: e21, touch: G5(e21) };
        }(e20));
      }, Z5 = function(e20) {
        for (var t15 = 0; t15 < K5.length; t15++) {
          if (K5[t15].event.pointerId === e20.pointerId)
            return void K5.splice(t15, 1);
        }
      }, $6 = function(e20) {
        e20.touches = K5.map(function(e21) {
          return e21.touch;
        });
      }, Q5 = function(e20) {
        return "mouse" === e20.pointerType || 4 === e20.pointerType;
      };
      e19.registerBinding(e19.container, "pointerdown", function(e20) {
        Q5(e20) || (e20.preventDefault(), U6(e20), $6(e20), R7(e20));
      }), e19.registerBinding(e19.container, "pointerup", function(e20) {
        Q5(e20) || (Z5(e20), $6(e20), q7(e20));
      }), e19.registerBinding(e19.container, "pointercancel", function(e20) {
        Q5(e20) || (Z5(e20), $6(e20), F7());
      }), e19.registerBinding(e19.container, "pointermove", function(e20) {
        Q5(e20) || (e20.preventDefault(), function(e21) {
          var t15 = K5.filter(function(t16) {
            return t16.event.pointerId === e21.pointerId;
          })[0];
          t15.event = e21, t15.touch = G5(e21);
        }(e20), $6(e20), V6(e20));
      });
    }
  };
  var ms = { generatePolygon: function(e19, t14) {
    return this.nodeShapes[e19] = { renderer: this, name: e19, points: t14, draw: function(e20, t15, n11, r8, a8) {
      this.renderer.nodeShapeImpl("polygon", e20, t15, n11, r8, a8, this.points);
    }, intersectLine: function(e20, t15, n11, r8, a8, i9, o11) {
      return Ot4(a8, i9, this.points, e20, t15, n11 / 2, r8 / 2, o11);
    }, checkPoint: function(e20, t15, n11, r8, a8, i9, o11) {
      return Bt4(e20, t15, this.points, i9, o11, r8, a8, [0, -1], n11);
    } };
  } };
  ms.generateEllipse = function() {
    return this.nodeShapes.ellipse = { renderer: this, name: "ellipse", draw: function(e19, t14, n11, r8, a8) {
      this.renderer.nodeShapeImpl(this.name, e19, t14, n11, r8, a8);
    }, intersectLine: function(e19, t14, n11, r8, a8, i9, o11) {
      return function(e20, t15, n12, r9, a9, i10) {
        var o12 = n12 - e20, s10 = r9 - t15;
        o12 /= a9, s10 /= i10;
        var l10 = Math.sqrt(o12 * o12 + s10 * s10), u9 = l10 - 1;
        if (u9 < 0)
          return [];
        var c9 = u9 / l10;
        return [(n12 - e20) * c9 + e20, (r9 - t15) * c9 + t15];
      }(a8, i9, e19, t14, n11 / 2 + o11, r8 / 2 + o11);
    }, checkPoint: function(e19, t14, n11, r8, a8, i9, o11) {
      return It4(e19, t14, r8, a8, i9, o11, n11);
    } };
  }, ms.generateRoundPolygon = function(e19, t14) {
    for (var n11 = new Array(2 * t14.length), r8 = 0; r8 < t14.length / 2; r8++) {
      var a8 = 2 * r8, i9 = void 0;
      i9 = r8 < t14.length / 2 - 1 ? 2 * (r8 + 1) : 0, n11[4 * r8] = t14[a8], n11[4 * r8 + 1] = t14[a8 + 1];
      var o11 = t14[i9] - t14[a8], s10 = t14[i9 + 1] - t14[a8 + 1], l10 = Math.sqrt(o11 * o11 + s10 * s10);
      n11[4 * r8 + 2] = o11 / l10, n11[4 * r8 + 3] = s10 / l10;
    }
    return this.nodeShapes[e19] = { renderer: this, name: e19, points: n11, draw: function(e20, t15, n12, r9, a9) {
      this.renderer.nodeShapeImpl("round-polygon", e20, t15, n12, r9, a9, this.points);
    }, intersectLine: function(e20, t15, n12, r9, a9, i10, o12) {
      return function(e21, t16, n13, r10, a10, i11, o13, s11) {
        for (var l11, u9 = [], c9 = new Array(n13.length), d10 = i11 / 2, h9 = o13 / 2, p9 = Yt4(i11, o13), f10 = 0; f10 < n13.length / 4; f10++) {
          var g8, v11 = void 0;
          v11 = 0 === f10 ? n13.length - 2 : 4 * f10 - 2, g8 = 4 * f10 + 2;
          var y9 = r10 + d10 * n13[4 * f10], m11 = a10 + h9 * n13[4 * f10 + 1], b10 = -n13[v11] * n13[g8] - n13[v11 + 1] * n13[g8 + 1], x10 = p9 / Math.tan(Math.acos(b10) / 2), w9 = y9 - x10 * n13[v11], E8 = m11 - x10 * n13[v11 + 1], k9 = y9 + x10 * n13[g8], C8 = m11 + x10 * n13[g8 + 1];
          0 === f10 ? (c9[n13.length - 2] = w9, c9[n13.length - 1] = E8) : (c9[4 * f10 - 2] = w9, c9[4 * f10 - 1] = E8), c9[4 * f10] = k9, c9[4 * f10 + 1] = C8;
          var S7 = n13[v11 + 1], D7 = -n13[v11];
          S7 * n13[g8] + D7 * n13[g8 + 1] < 0 && (S7 *= -1, D7 *= -1), 0 !== (l11 = zt4(e21, t16, r10, a10, w9 + S7 * p9, E8 + D7 * p9, p9)).length && u9.push(l11[0], l11[1]);
        }
        for (var P9 = 0; P9 < c9.length / 4; P9++)
          0 !== (l11 = At4(e21, t16, r10, a10, c9[4 * P9], c9[4 * P9 + 1], c9[4 * P9 + 2], c9[4 * P9 + 3], false)).length && u9.push(l11[0], l11[1]);
        if (u9.length > 2) {
          for (var T8 = [u9[0], u9[1]], M8 = Math.pow(T8[0] - e21, 2) + Math.pow(T8[1] - t16, 2), B8 = 1; B8 < u9.length / 2; B8++) {
            var _6 = Math.pow(u9[2 * B8] - e21, 2) + Math.pow(u9[2 * B8 + 1] - t16, 2);
            _6 <= M8 && (T8[0] = u9[2 * B8], T8[1] = u9[2 * B8 + 1], M8 = _6);
          }
          return T8;
        }
        return u9;
      }(a9, i10, this.points, e20, t15, n12, r9);
    }, checkPoint: function(e20, t15, n12, r9, a9, i10, o12) {
      return function(e21, t16, n13, r10, a10, i11, o13) {
        for (var s11 = new Array(n13.length), l11 = i11 / 2, u9 = o13 / 2, c9 = Yt4(i11, o13), d10 = c9 * c9, h9 = 0; h9 < n13.length / 4; h9++) {
          var p9, f10 = void 0;
          f10 = 0 === h9 ? n13.length - 2 : 4 * h9 - 2, p9 = 4 * h9 + 2;
          var g8 = r10 + l11 * n13[4 * h9], v11 = a10 + u9 * n13[4 * h9 + 1], y9 = -n13[f10] * n13[p9] - n13[f10 + 1] * n13[p9 + 1], m11 = c9 / Math.tan(Math.acos(y9) / 2), b10 = g8 - m11 * n13[f10], x10 = v11 - m11 * n13[f10 + 1], w9 = g8 + m11 * n13[p9], E8 = v11 + m11 * n13[p9 + 1];
          s11[4 * h9] = b10, s11[4 * h9 + 1] = x10, s11[4 * h9 + 2] = w9, s11[4 * h9 + 3] = E8;
          var k9 = n13[f10 + 1], C8 = -n13[f10];
          k9 * n13[p9] + C8 * n13[p9 + 1] < 0 && (k9 *= -1, C8 *= -1);
          var S7 = b10 + k9 * c9, D7 = x10 + C8 * c9;
          if (Math.pow(S7 - e21, 2) + Math.pow(D7 - t16, 2) <= d10)
            return true;
        }
        return Mt4(e21, t16, s11);
      }(e20, t15, this.points, i10, o12, r9, a9);
    } };
  }, ms.generateRoundRectangle = function() {
    return this.nodeShapes["round-rectangle"] = this.nodeShapes.roundrectangle = { renderer: this, name: "round-rectangle", points: Vt4(4, 0), draw: function(e19, t14, n11, r8, a8) {
      this.renderer.nodeShapeImpl(this.name, e19, t14, n11, r8, a8);
    }, intersectLine: function(e19, t14, n11, r8, a8, i9, o11) {
      return Ct4(a8, i9, e19, t14, n11, r8, o11);
    }, checkPoint: function(e19, t14, n11, r8, a8, i9, o11) {
      var s10 = jt4(r8, a8), l10 = 2 * s10;
      return !!Bt4(e19, t14, this.points, i9, o11, r8, a8 - l10, [0, -1], n11) || (!!Bt4(e19, t14, this.points, i9, o11, r8 - l10, a8, [0, -1], n11) || (!!It4(e19, t14, l10, l10, i9 - r8 / 2 + s10, o11 - a8 / 2 + s10, n11) || (!!It4(e19, t14, l10, l10, i9 + r8 / 2 - s10, o11 - a8 / 2 + s10, n11) || (!!It4(e19, t14, l10, l10, i9 + r8 / 2 - s10, o11 + a8 / 2 - s10, n11) || !!It4(e19, t14, l10, l10, i9 - r8 / 2 + s10, o11 + a8 / 2 - s10, n11)))));
    } };
  }, ms.generateCutRectangle = function() {
    return this.nodeShapes["cut-rectangle"] = this.nodeShapes.cutrectangle = { renderer: this, name: "cut-rectangle", cornerLength: 8, points: Vt4(4, 0), draw: function(e19, t14, n11, r8, a8) {
      this.renderer.nodeShapeImpl(this.name, e19, t14, n11, r8, a8);
    }, generateCutTrianglePts: function(e19, t14, n11, r8) {
      var a8 = this.cornerLength, i9 = t14 / 2, o11 = e19 / 2, s10 = n11 - o11, l10 = n11 + o11, u9 = r8 - i9, c9 = r8 + i9;
      return { topLeft: [s10, u9 + a8, s10 + a8, u9, s10 + a8, u9 + a8], topRight: [l10 - a8, u9, l10, u9 + a8, l10 - a8, u9 + a8], bottomRight: [l10, c9 - a8, l10 - a8, c9, l10 - a8, c9 - a8], bottomLeft: [s10 + a8, c9, s10, c9 - a8, s10 + a8, c9 - a8] };
    }, intersectLine: function(e19, t14, n11, r8, a8, i9, o11) {
      var s10 = this.generateCutTrianglePts(n11 + 2 * o11, r8 + 2 * o11, e19, t14), l10 = [].concat.apply([], [s10.topLeft.splice(0, 4), s10.topRight.splice(0, 4), s10.bottomRight.splice(0, 4), s10.bottomLeft.splice(0, 4)]);
      return Ot4(a8, i9, l10, e19, t14);
    }, checkPoint: function(e19, t14, n11, r8, a8, i9, o11) {
      if (Bt4(e19, t14, this.points, i9, o11, r8, a8 - 2 * this.cornerLength, [0, -1], n11))
        return true;
      if (Bt4(e19, t14, this.points, i9, o11, r8 - 2 * this.cornerLength, a8, [0, -1], n11))
        return true;
      var s10 = this.generateCutTrianglePts(r8, a8, i9, o11);
      return Mt4(e19, t14, s10.topLeft) || Mt4(e19, t14, s10.topRight) || Mt4(e19, t14, s10.bottomRight) || Mt4(e19, t14, s10.bottomLeft);
    } };
  }, ms.generateBarrel = function() {
    return this.nodeShapes.barrel = { renderer: this, name: "barrel", points: Vt4(4, 0), draw: function(e19, t14, n11, r8, a8) {
      this.renderer.nodeShapeImpl(this.name, e19, t14, n11, r8, a8);
    }, intersectLine: function(e19, t14, n11, r8, a8, i9, o11) {
      var s10 = this.generateBarrelBezierPts(n11 + 2 * o11, r8 + 2 * o11, e19, t14), l10 = function(e20) {
        var t15 = ft4({ x: e20[0], y: e20[1] }, { x: e20[2], y: e20[3] }, { x: e20[4], y: e20[5] }, 0.15), n12 = ft4({ x: e20[0], y: e20[1] }, { x: e20[2], y: e20[3] }, { x: e20[4], y: e20[5] }, 0.5), r9 = ft4({ x: e20[0], y: e20[1] }, { x: e20[2], y: e20[3] }, { x: e20[4], y: e20[5] }, 0.85);
        return [e20[0], e20[1], t15.x, t15.y, n12.x, n12.y, r9.x, r9.y, e20[4], e20[5]];
      }, u9 = [].concat(l10(s10.topLeft), l10(s10.topRight), l10(s10.bottomRight), l10(s10.bottomLeft));
      return Ot4(a8, i9, u9, e19, t14);
    }, generateBarrelBezierPts: function(e19, t14, n11, r8) {
      var a8 = t14 / 2, i9 = e19 / 2, o11 = n11 - i9, s10 = n11 + i9, l10 = r8 - a8, u9 = r8 + a8, c9 = Xt4(e19, t14), d10 = c9.heightOffset, h9 = c9.widthOffset, p9 = c9.ctrlPtOffsetPct * e19, f10 = { topLeft: [o11, l10 + d10, o11 + p9, l10, o11 + h9, l10], topRight: [s10 - h9, l10, s10 - p9, l10, s10, l10 + d10], bottomRight: [s10, u9 - d10, s10 - p9, u9, s10 - h9, u9], bottomLeft: [o11 + h9, u9, o11 + p9, u9, o11, u9 - d10] };
      return f10.topLeft.isTop = true, f10.topRight.isTop = true, f10.bottomLeft.isBottom = true, f10.bottomRight.isBottom = true, f10;
    }, checkPoint: function(e19, t14, n11, r8, a8, i9, o11) {
      var s10 = Xt4(r8, a8), l10 = s10.heightOffset, u9 = s10.widthOffset;
      if (Bt4(e19, t14, this.points, i9, o11, r8, a8 - 2 * l10, [0, -1], n11))
        return true;
      if (Bt4(e19, t14, this.points, i9, o11, r8 - 2 * u9, a8, [0, -1], n11))
        return true;
      for (var c9 = this.generateBarrelBezierPts(r8, a8, i9, o11), d10 = function(e20, t15, n12) {
        var r9, a9, i10 = n12[4], o12 = n12[2], s11 = n12[0], l11 = n12[5], u10 = n12[1], c10 = Math.min(i10, s11), d11 = Math.max(i10, s11), h10 = Math.min(l11, u10), p10 = Math.max(l11, u10);
        if (c10 <= e20 && e20 <= d11 && h10 <= t15 && t15 <= p10) {
          var f11 = [(r9 = i10) - 2 * (a9 = o12) + s11, 2 * (a9 - r9), r9], g9 = function(e21, t16, n13, r10) {
            var a10 = t16 * t16 - 4 * e21 * (n13 -= r10);
            if (a10 < 0)
              return [];
            var i11 = Math.sqrt(a10), o13 = 2 * e21;
            return [(-t16 + i11) / o13, (-t16 - i11) / o13];
          }(f11[0], f11[1], f11[2], e20).filter(function(e21) {
            return 0 <= e21 && e21 <= 1;
          });
          if (g9.length > 0)
            return g9[0];
        }
        return null;
      }, h9 = Object.keys(c9), p9 = 0; p9 < h9.length; p9++) {
        var f10 = c9[h9[p9]], g8 = d10(e19, t14, f10);
        if (null != g8) {
          var v11 = f10[5], y9 = f10[3], m11 = f10[1], b10 = pt4(v11, y9, m11, g8);
          if (f10.isTop && b10 <= t14)
            return true;
          if (f10.isBottom && t14 <= b10)
            return true;
        }
      }
      return false;
    } };
  }, ms.generateBottomRoundrectangle = function() {
    return this.nodeShapes["bottom-round-rectangle"] = this.nodeShapes.bottomroundrectangle = { renderer: this, name: "bottom-round-rectangle", points: Vt4(4, 0), draw: function(e19, t14, n11, r8, a8) {
      this.renderer.nodeShapeImpl(this.name, e19, t14, n11, r8, a8);
    }, intersectLine: function(e19, t14, n11, r8, a8, i9, o11) {
      var s10 = t14 - (r8 / 2 + o11), l10 = At4(a8, i9, e19, t14, e19 - (n11 / 2 + o11), s10, e19 + (n11 / 2 + o11), s10, false);
      return l10.length > 0 ? l10 : Ct4(a8, i9, e19, t14, n11, r8, o11);
    }, checkPoint: function(e19, t14, n11, r8, a8, i9, o11) {
      var s10 = jt4(r8, a8), l10 = 2 * s10;
      if (Bt4(e19, t14, this.points, i9, o11, r8, a8 - l10, [0, -1], n11))
        return true;
      if (Bt4(e19, t14, this.points, i9, o11, r8 - l10, a8, [0, -1], n11))
        return true;
      var u9 = r8 / 2 + 2 * n11, c9 = a8 / 2 + 2 * n11;
      return !!Mt4(e19, t14, [i9 - u9, o11 - c9, i9 - u9, o11, i9 + u9, o11, i9 + u9, o11 - c9]) || (!!It4(e19, t14, l10, l10, i9 + r8 / 2 - s10, o11 + a8 / 2 - s10, n11) || !!It4(e19, t14, l10, l10, i9 - r8 / 2 + s10, o11 + a8 / 2 - s10, n11));
    } };
  }, ms.registerNodeShapes = function() {
    var e19 = this.nodeShapes = {}, t14 = this;
    this.generateEllipse(), this.generatePolygon("triangle", Vt4(3, 0)), this.generateRoundPolygon("round-triangle", Vt4(3, 0)), this.generatePolygon("rectangle", Vt4(4, 0)), e19.square = e19.rectangle, this.generateRoundRectangle(), this.generateCutRectangle(), this.generateBarrel(), this.generateBottomRoundrectangle();
    var n11 = [0, 1, 1, 0, 0, -1, -1, 0];
    this.generatePolygon("diamond", n11), this.generateRoundPolygon("round-diamond", n11), this.generatePolygon("pentagon", Vt4(5, 0)), this.generateRoundPolygon("round-pentagon", Vt4(5, 0)), this.generatePolygon("hexagon", Vt4(6, 0)), this.generateRoundPolygon("round-hexagon", Vt4(6, 0)), this.generatePolygon("heptagon", Vt4(7, 0)), this.generateRoundPolygon("round-heptagon", Vt4(7, 0)), this.generatePolygon("octagon", Vt4(8, 0)), this.generateRoundPolygon("round-octagon", Vt4(8, 0));
    var r8 = new Array(20), a8 = qt4(5, 0), i9 = qt4(5, Math.PI / 5), o11 = 0.5 * (3 - Math.sqrt(5));
    o11 *= 1.57;
    for (var s10 = 0; s10 < i9.length / 2; s10++)
      i9[2 * s10] *= o11, i9[2 * s10 + 1] *= o11;
    for (s10 = 0; s10 < 5; s10++)
      r8[4 * s10] = a8[2 * s10], r8[4 * s10 + 1] = a8[2 * s10 + 1], r8[4 * s10 + 2] = i9[2 * s10], r8[4 * s10 + 3] = i9[2 * s10 + 1];
    r8 = Ft4(r8), this.generatePolygon("star", r8), this.generatePolygon("vee", [-1, -1, 0, -0.333, 1, -1, 0, 1]), this.generatePolygon("rhomboid", [-1, -1, 0.333, -1, 1, 1, -0.333, 1]), this.generatePolygon("right-rhomboid", [-0.333, -1, 1, -1, 0.333, 1, -1, 1]), this.nodeShapes.concavehexagon = this.generatePolygon("concave-hexagon", [-1, -0.95, -0.75, 0, -1, 0.95, 1, 0.95, 0.75, 0, 1, -0.95]);
    var l10 = [-1, -1, 0.25, -1, 1, 0, 0.25, 1, -1, 1];
    this.generatePolygon("tag", l10), this.generateRoundPolygon("round-tag", l10), e19.makePolygon = function(e20) {
      var n12, r9 = "polygon-" + e20.join("$");
      return (n12 = this[r9]) ? n12 : t14.generatePolygon(r9, e20);
    };
  };
  var bs = { timeToRender: function() {
    return this.redrawTotalTime / this.redrawCount;
  }, redraw: function(e19) {
    e19 = e19 || Ie();
    var t14 = this;
    void 0 === t14.averageRedrawTime && (t14.averageRedrawTime = 0), void 0 === t14.lastRedrawTime && (t14.lastRedrawTime = 0), void 0 === t14.lastDrawTime && (t14.lastDrawTime = 0), t14.requestedFrame = true, t14.renderOptions = e19;
  }, beforeRender: function(e19, t14) {
    if (!this.destroyed) {
      null == t14 && Pe("Priority is not optional for beforeRender");
      var n11 = this.beforeRenderCallbacks;
      n11.push({ fn: e19, priority: t14 }), n11.sort(function(e20, t15) {
        return t15.priority - e20.priority;
      });
    }
  } };
  var xs = function(e19, t14, n11) {
    for (var r8 = e19.beforeRenderCallbacks, a8 = 0; a8 < r8.length; a8++)
      r8[a8].fn(t14, n11);
  };
  bs.startRenderLoop = function() {
    var e19 = this, t14 = e19.cy;
    if (!e19.renderLoopStarted) {
      e19.renderLoopStarted = true;
      se(function n11(r8) {
        if (!e19.destroyed) {
          if (t14.batching())
            ;
          else if (e19.requestedFrame && !e19.skipFrame) {
            xs(e19, true, r8);
            var a8 = le();
            e19.render(e19.renderOptions);
            var i9 = e19.lastDrawTime = le();
            void 0 === e19.averageRedrawTime && (e19.averageRedrawTime = i9 - a8), void 0 === e19.redrawCount && (e19.redrawCount = 0), e19.redrawCount++, void 0 === e19.redrawTotalTime && (e19.redrawTotalTime = 0);
            var o11 = i9 - a8;
            e19.redrawTotalTime += o11, e19.lastRedrawTime = o11, e19.averageRedrawTime = e19.averageRedrawTime / 2 + o11 / 2, e19.requestedFrame = false;
          } else
            xs(e19, false, r8);
          e19.skipFrame = false, se(n11);
        }
      });
    }
  };
  var ws = function(e19) {
    this.init(e19);
  };
  var Es = ws.prototype;
  Es.clientFunctions = ["redrawHint", "render", "renderTo", "matchCanvasSize", "nodeShapeImpl", "arrowShapeImpl"], Es.init = function(e19) {
    var t14 = this;
    t14.options = e19, t14.cy = e19.cy;
    var n11 = t14.container = e19.cy.container(), r8 = t14.cy.window();
    if (r8) {
      var a8 = r8.document, i9 = a8.head, o11 = "__________cytoscape_stylesheet", s10 = "__________cytoscape_container", l10 = null != a8.getElementById(o11);
      if (n11.className.indexOf(s10) < 0 && (n11.className = (n11.className || "") + " " + s10), !l10) {
        var u9 = a8.createElement("style");
        u9.id = o11, u9.textContent = "." + s10 + " { position: relative; }", i9.insertBefore(u9, i9.children[0]);
      }
      "static" === r8.getComputedStyle(n11).getPropertyValue("position") && Me("A Cytoscape container has style position:static and so can not use UI extensions properly");
    }
    t14.selection = [void 0, void 0, void 0, void 0, 0], t14.bezierProjPcts = [0.05, 0.225, 0.4, 0.5, 0.6, 0.775, 0.95], t14.hoverData = { down: null, last: null, downTime: null, triggerMode: null, dragging: false, initialPan: [null, null], capture: false }, t14.dragData = { possibleDragElements: [] }, t14.touchData = { start: null, capture: false, startPosition: [null, null, null, null, null, null], singleTouchStartTime: null, singleTouchMoved: true, now: [null, null, null, null, null, null], earlier: [null, null, null, null, null, null] }, t14.redraws = 0, t14.showFps = e19.showFps, t14.debug = e19.debug, t14.hideEdgesOnViewport = e19.hideEdgesOnViewport, t14.textureOnViewport = e19.textureOnViewport, t14.wheelSensitivity = e19.wheelSensitivity, t14.motionBlurEnabled = e19.motionBlur, t14.forcedPixelRatio = I6(e19.pixelRatio) ? e19.pixelRatio : null, t14.motionBlur = e19.motionBlur, t14.motionBlurOpacity = e19.motionBlurOpacity, t14.motionBlurTransparency = 1 - t14.motionBlurOpacity, t14.motionBlurPxRatio = 1, t14.mbPxRBlurry = 1, t14.minMbLowQualFrames = 4, t14.fullQualityMb = false, t14.clearedForMotionBlur = [], t14.desktopTapThreshold = e19.desktopTapThreshold, t14.desktopTapThreshold2 = e19.desktopTapThreshold * e19.desktopTapThreshold, t14.touchTapThreshold = e19.touchTapThreshold, t14.touchTapThreshold2 = e19.touchTapThreshold * e19.touchTapThreshold, t14.tapholdDuration = 500, t14.bindings = [], t14.beforeRenderCallbacks = [], t14.beforeRenderPriorities = { animations: 400, eleCalcs: 300, eleTxrDeq: 200, lyrTxrDeq: 150, lyrTxrSkip: 100 }, t14.registerNodeShapes(), t14.registerArrowShapes(), t14.registerCalculationListeners();
  }, Es.notify = function(e19, t14) {
    var n11 = this, r8 = n11.cy;
    this.destroyed || ("init" !== e19 ? "destroy" !== e19 ? (("add" === e19 || "remove" === e19 || "move" === e19 && r8.hasCompoundNodes() || "load" === e19 || "zorder" === e19 || "mount" === e19) && n11.invalidateCachedZSortedEles(), "viewport" === e19 && n11.redrawHint("select", true), "load" !== e19 && "resize" !== e19 && "mount" !== e19 || (n11.invalidateContainerClientCoordsCache(), n11.matchCanvasSize(n11.container)), n11.redrawHint("eles", true), n11.redrawHint("drag", true), this.startRenderLoop(), this.redraw()) : n11.destroy() : n11.load());
  }, Es.destroy = function() {
    var e19 = this;
    e19.destroyed = true, e19.cy.stopAnimationLoop();
    for (var t14 = 0; t14 < e19.bindings.length; t14++) {
      var n11 = e19.bindings[t14], r8 = n11.target;
      (r8.off || r8.removeEventListener).apply(r8, n11.args);
    }
    if (e19.bindings = [], e19.beforeRenderCallbacks = [], e19.onUpdateEleCalcsFns = [], e19.removeObserver && e19.removeObserver.disconnect(), e19.styleObserver && e19.styleObserver.disconnect(), e19.resizeObserver && e19.resizeObserver.disconnect(), e19.labelCalcDiv)
      try {
        document.body.removeChild(e19.labelCalcDiv);
      } catch (e20) {
      }
  }, Es.isHeadless = function() {
    return false;
  }, [es, gs, vs, ys, ms, bs].forEach(function(e19) {
    J4(Es, e19);
  });
  var ks = 1e3 / 60;
  var Cs = function(e19) {
    return function() {
      var t14 = this, n11 = this.renderer;
      if (!t14.dequeueingSetup) {
        t14.dequeueingSetup = true;
        var r8 = c6.default(function() {
          n11.redrawHint("eles", true), n11.redrawHint("drag", true), n11.redraw();
        }, e19.deqRedrawThreshold), a8 = e19.priority || De;
        n11.beforeRender(function(a9, i9) {
          var o11 = le(), s10 = n11.averageRedrawTime, l10 = n11.lastRedrawTime, u9 = [], c9 = n11.cy.extent(), d10 = n11.getPixelRatio();
          for (a9 || n11.flushRenderedStyleQueue(); ; ) {
            var h9 = le(), p9 = h9 - o11, f10 = h9 - i9;
            if (l10 < ks) {
              var g8 = ks - (a9 ? s10 : 0);
              if (f10 >= e19.deqFastCost * g8)
                break;
            } else if (a9) {
              if (p9 >= e19.deqCost * l10 || p9 >= e19.deqAvgCost * s10)
                break;
            } else if (f10 >= e19.deqNoDrawCost * ks)
              break;
            var v11 = e19.deq(t14, d10, c9);
            if (!(v11.length > 0))
              break;
            for (var y9 = 0; y9 < v11.length; y9++)
              u9.push(v11[y9]);
          }
          u9.length > 0 && (e19.onDeqd(t14, u9), !a9 && e19.shouldRedraw(t14, u9, d10, c9) && r8());
        }, a8(t14));
      }
    };
  };
  var Ss = function() {
    function e19(t14) {
      var n11 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : Ce;
      v6(this, e19), this.idsByKey = new Ve(), this.keyForId = new Ve(), this.cachesByLvl = new Ve(), this.lvls = [], this.getKey = t14, this.doesEleInvalidateKey = n11;
    }
    return m7(e19, [{ key: "getIdsFor", value: function(e20) {
      null == e20 && Pe("Can not get id list for null key");
      var t14 = this.idsByKey, n11 = this.idsByKey.get(e20);
      return n11 || (n11 = new qe(), t14.set(e20, n11)), n11;
    } }, { key: "addIdForKey", value: function(e20, t14) {
      null != e20 && this.getIdsFor(e20).add(t14);
    } }, { key: "deleteIdForKey", value: function(e20, t14) {
      null != e20 && this.getIdsFor(e20).delete(t14);
    } }, { key: "getNumberOfIdsForKey", value: function(e20) {
      return null == e20 ? 0 : this.getIdsFor(e20).size;
    } }, { key: "updateKeyMappingFor", value: function(e20) {
      var t14 = e20.id(), n11 = this.keyForId.get(t14), r8 = this.getKey(e20);
      this.deleteIdForKey(n11, t14), this.addIdForKey(r8, t14), this.keyForId.set(t14, r8);
    } }, { key: "deleteKeyMappingFor", value: function(e20) {
      var t14 = e20.id(), n11 = this.keyForId.get(t14);
      this.deleteIdForKey(n11, t14), this.keyForId.delete(t14);
    } }, { key: "keyHasChangedFor", value: function(e20) {
      var t14 = e20.id();
      return this.keyForId.get(t14) !== this.getKey(e20);
    } }, { key: "isInvalid", value: function(e20) {
      return this.keyHasChangedFor(e20) || this.doesEleInvalidateKey(e20);
    } }, { key: "getCachesAt", value: function(e20) {
      var t14 = this.cachesByLvl, n11 = this.lvls, r8 = t14.get(e20);
      return r8 || (r8 = new Ve(), t14.set(e20, r8), n11.push(e20)), r8;
    } }, { key: "getCache", value: function(e20, t14) {
      return this.getCachesAt(t14).get(e20);
    } }, { key: "get", value: function(e20, t14) {
      var n11 = this.getKey(e20), r8 = this.getCache(n11, t14);
      return null != r8 && this.updateKeyMappingFor(e20), r8;
    } }, { key: "getForCachedKey", value: function(e20, t14) {
      var n11 = this.keyForId.get(e20.id());
      return this.getCache(n11, t14);
    } }, { key: "hasCache", value: function(e20, t14) {
      return this.getCachesAt(t14).has(e20);
    } }, { key: "has", value: function(e20, t14) {
      var n11 = this.getKey(e20);
      return this.hasCache(n11, t14);
    } }, { key: "setCache", value: function(e20, t14, n11) {
      n11.key = e20, this.getCachesAt(t14).set(e20, n11);
    } }, { key: "set", value: function(e20, t14, n11) {
      var r8 = this.getKey(e20);
      this.setCache(r8, t14, n11), this.updateKeyMappingFor(e20);
    } }, { key: "deleteCache", value: function(e20, t14) {
      this.getCachesAt(t14).delete(e20);
    } }, { key: "delete", value: function(e20, t14) {
      var n11 = this.getKey(e20);
      this.deleteCache(n11, t14);
    } }, { key: "invalidateKey", value: function(e20) {
      var t14 = this;
      this.lvls.forEach(function(n11) {
        return t14.deleteCache(e20, n11);
      });
    } }, { key: "invalidate", value: function(e20) {
      var t14 = e20.id(), n11 = this.keyForId.get(t14);
      this.deleteKeyMappingFor(e20);
      var r8 = this.doesEleInvalidateKey(e20);
      return r8 && this.invalidateKey(n11), r8 || 0 === this.getNumberOfIdsForKey(n11);
    } }]), e19;
  }();
  var Ds = { dequeue: "dequeue", downscale: "downscale", highQuality: "highQuality" };
  var Ps = ze({ getKey: null, doesEleInvalidateKey: Ce, drawElement: null, getBoundingBox: null, getRotationPoint: null, getRotationOffset: null, isVisible: ke, allowEdgeTxrCaching: true, allowParentTxrCaching: true });
  var Ts = function(e19, t14) {
    var n11 = this;
    n11.renderer = e19, n11.onDequeues = [];
    var r8 = Ps(t14);
    J4(n11, r8), n11.lookup = new Ss(r8.getKey, r8.doesEleInvalidateKey), n11.setupDequeueing();
  };
  var Ms = Ts.prototype;
  Ms.reasons = Ds, Ms.getTextureQueue = function(e19) {
    var t14 = this;
    return t14.eleImgCaches = t14.eleImgCaches || {}, t14.eleImgCaches[e19] = t14.eleImgCaches[e19] || [];
  }, Ms.getRetiredTextureQueue = function(e19) {
    var t14 = this.eleImgCaches.retired = this.eleImgCaches.retired || {};
    return t14[e19] = t14[e19] || [];
  }, Ms.getElementQueue = function() {
    return this.eleCacheQueue = this.eleCacheQueue || new d6.default(function(e19, t14) {
      return t14.reqs - e19.reqs;
    });
  }, Ms.getElementKeyToQueue = function() {
    return this.eleKeyToCacheQueue = this.eleKeyToCacheQueue || {};
  }, Ms.getElement = function(e19, t14, n11, r8, a8) {
    var i9 = this, o11 = this.renderer, s10 = o11.cy.zoom(), l10 = this.lookup;
    if (!t14 || 0 === t14.w || 0 === t14.h || isNaN(t14.w) || isNaN(t14.h) || !e19.visible() || e19.removed())
      return null;
    if (!i9.allowEdgeTxrCaching && e19.isEdge() || !i9.allowParentTxrCaching && e19.isParent())
      return null;
    if (null == r8 && (r8 = Math.ceil(lt4(s10 * n11))), r8 < -4)
      r8 = -4;
    else if (s10 >= 7.99 || r8 > 3)
      return null;
    var u9 = Math.pow(2, r8), c9 = t14.h * u9, d10 = t14.w * u9, h9 = o11.eleTextBiggerThanMin(e19, u9);
    if (!this.isVisible(e19, h9))
      return null;
    var p9, f10 = l10.get(e19, r8);
    if (f10 && f10.invalidated && (f10.invalidated = false, f10.texture.invalidatedWidth -= f10.width), f10)
      return f10;
    if (p9 = c9 <= 25 ? 25 : c9 <= 50 ? 50 : 50 * Math.ceil(c9 / 50), c9 > 1024 || d10 > 1024)
      return null;
    var g8 = i9.getTextureQueue(p9), v11 = g8[g8.length - 2], y9 = function() {
      return i9.recycleTexture(p9, d10) || i9.addTexture(p9, d10);
    };
    v11 || (v11 = g8[g8.length - 1]), v11 || (v11 = y9()), v11.width - v11.usedWidth < d10 && (v11 = y9());
    for (var m11, b10 = function(e20) {
      return e20 && e20.scaledLabelShown === h9;
    }, x10 = a8 && a8 === Ds.dequeue, w9 = a8 && a8 === Ds.highQuality, E8 = a8 && a8 === Ds.downscale, k9 = r8 + 1; k9 <= 3; k9++) {
      var C8 = l10.get(e19, k9);
      if (C8) {
        m11 = C8;
        break;
      }
    }
    var S7 = m11 && m11.level === r8 + 1 ? m11 : null, D7 = function() {
      v11.context.drawImage(S7.texture.canvas, S7.x, 0, S7.width, S7.height, v11.usedWidth, 0, d10, c9);
    };
    if (v11.context.setTransform(1, 0, 0, 1, 0, 0), v11.context.clearRect(v11.usedWidth, 0, d10, p9), b10(S7))
      D7();
    else if (b10(m11)) {
      if (!w9)
        return i9.queueElement(e19, m11.level - 1), m11;
      for (var P9 = m11.level; P9 > r8; P9--)
        S7 = i9.getElement(e19, t14, n11, P9, Ds.downscale);
      D7();
    } else {
      var T8;
      if (!x10 && !w9 && !E8)
        for (var M8 = r8 - 1; M8 >= -4; M8--) {
          var B8 = l10.get(e19, M8);
          if (B8) {
            T8 = B8;
            break;
          }
        }
      if (b10(T8))
        return i9.queueElement(e19, r8), T8;
      v11.context.translate(v11.usedWidth, 0), v11.context.scale(u9, u9), this.drawElement(v11.context, e19, t14, h9, false), v11.context.scale(1 / u9, 1 / u9), v11.context.translate(-v11.usedWidth, 0);
    }
    return f10 = { x: v11.usedWidth, texture: v11, level: r8, scale: u9, width: d10, height: c9, scaledLabelShown: h9 }, v11.usedWidth += Math.ceil(d10 + 8), v11.eleCaches.push(f10), l10.set(e19, r8, f10), i9.checkTextureFullness(v11), f10;
  }, Ms.invalidateElements = function(e19) {
    for (var t14 = 0; t14 < e19.length; t14++)
      this.invalidateElement(e19[t14]);
  }, Ms.invalidateElement = function(e19) {
    var t14 = this, n11 = t14.lookup, r8 = [];
    if (n11.isInvalid(e19)) {
      for (var a8 = -4; a8 <= 3; a8++) {
        var i9 = n11.getForCachedKey(e19, a8);
        i9 && r8.push(i9);
      }
      if (n11.invalidate(e19))
        for (var o11 = 0; o11 < r8.length; o11++) {
          var s10 = r8[o11], l10 = s10.texture;
          l10.invalidatedWidth += s10.width, s10.invalidated = true, t14.checkTextureUtility(l10);
        }
      t14.removeFromQueue(e19);
    }
  }, Ms.checkTextureUtility = function(e19) {
    e19.invalidatedWidth >= 0.2 * e19.width && this.retireTexture(e19);
  }, Ms.checkTextureFullness = function(e19) {
    var t14 = this.getTextureQueue(e19.height);
    e19.usedWidth / e19.width > 0.8 && e19.fullnessChecks >= 10 ? Le(t14, e19) : e19.fullnessChecks++;
  }, Ms.retireTexture = function(e19) {
    var t14 = e19.height, n11 = this.getTextureQueue(t14), r8 = this.lookup;
    Le(n11, e19), e19.retired = true;
    for (var a8 = e19.eleCaches, i9 = 0; i9 < a8.length; i9++) {
      var o11 = a8[i9];
      r8.deleteCache(o11.key, o11.level);
    }
    Ae(a8), this.getRetiredTextureQueue(t14).push(e19);
  }, Ms.addTexture = function(e19, t14) {
    var n11 = {};
    return this.getTextureQueue(e19).push(n11), n11.eleCaches = [], n11.height = e19, n11.width = Math.max(1024, t14), n11.usedWidth = 0, n11.invalidatedWidth = 0, n11.fullnessChecks = 0, n11.canvas = this.renderer.makeOffscreenCanvas(n11.width, n11.height), n11.context = n11.canvas.getContext("2d"), n11;
  }, Ms.recycleTexture = function(e19, t14) {
    for (var n11 = this.getTextureQueue(e19), r8 = this.getRetiredTextureQueue(e19), a8 = 0; a8 < r8.length; a8++) {
      var i9 = r8[a8];
      if (i9.width >= t14)
        return i9.retired = false, i9.usedWidth = 0, i9.invalidatedWidth = 0, i9.fullnessChecks = 0, Ae(i9.eleCaches), i9.context.setTransform(1, 0, 0, 1, 0, 0), i9.context.clearRect(0, 0, i9.width, i9.height), Le(r8, i9), n11.push(i9), i9;
    }
  }, Ms.queueElement = function(e19, t14) {
    var n11 = this.getElementQueue(), r8 = this.getElementKeyToQueue(), a8 = this.getKey(e19), i9 = r8[a8];
    if (i9)
      i9.level = Math.max(i9.level, t14), i9.eles.merge(e19), i9.reqs++, n11.updateItem(i9);
    else {
      var o11 = { eles: e19.spawn().merge(e19), level: t14, reqs: 1, key: a8 };
      n11.push(o11), r8[a8] = o11;
    }
  }, Ms.dequeue = function(e19) {
    for (var t14 = this, n11 = t14.getElementQueue(), r8 = t14.getElementKeyToQueue(), a8 = [], i9 = t14.lookup, o11 = 0; o11 < 1 && n11.size() > 0; o11++) {
      var s10 = n11.pop(), l10 = s10.key, u9 = s10.eles[0], c9 = i9.hasCache(u9, s10.level);
      if (r8[l10] = null, !c9) {
        a8.push(s10);
        var d10 = t14.getBoundingBox(u9);
        t14.getElement(u9, d10, e19, s10.level, Ds.dequeue);
      }
    }
    return a8;
  }, Ms.removeFromQueue = function(e19) {
    var t14 = this.getElementQueue(), n11 = this.getElementKeyToQueue(), r8 = this.getKey(e19), a8 = n11[r8];
    null != a8 && (1 === a8.eles.length ? (a8.reqs = Ee, t14.updateItem(a8), t14.pop(), n11[r8] = null) : a8.eles.unmerge(e19));
  }, Ms.onDequeue = function(e19) {
    this.onDequeues.push(e19);
  }, Ms.offDequeue = function(e19) {
    Le(this.onDequeues, e19);
  }, Ms.setupDequeueing = Cs({ deqRedrawThreshold: 100, deqCost: 0.15, deqAvgCost: 0.1, deqNoDrawCost: 0.9, deqFastCost: 0.9, deq: function(e19, t14, n11) {
    return e19.dequeue(t14, n11);
  }, onDeqd: function(e19, t14) {
    for (var n11 = 0; n11 < e19.onDequeues.length; n11++) {
      (0, e19.onDequeues[n11])(t14);
    }
  }, shouldRedraw: function(e19, t14, n11, r8) {
    for (var a8 = 0; a8 < t14.length; a8++)
      for (var i9 = t14[a8].eles, o11 = 0; o11 < i9.length; o11++) {
        var s10 = i9[o11].boundingBox();
        if (wt4(s10, r8))
          return true;
      }
    return false;
  }, priority: function(e19) {
    return e19.renderer.beforeRenderPriorities.eleTxrDeq;
  } });
  var Bs = function(e19) {
    var t14 = this, n11 = t14.renderer = e19, r8 = n11.cy;
    t14.layersByLevel = {}, t14.firstGet = true, t14.lastInvalidationTime = le() - 500, t14.skipping = false, t14.eleTxrDeqs = r8.collection(), t14.scheduleElementRefinement = c6.default(function() {
      t14.refineElementTextures(t14.eleTxrDeqs), t14.eleTxrDeqs.unmerge(t14.eleTxrDeqs);
    }, 50), n11.beforeRender(function(e20, n12) {
      n12 - t14.lastInvalidationTime <= 250 ? t14.skipping = true : t14.skipping = false;
    }, n11.beforeRenderPriorities.lyrTxrSkip);
    t14.layersQueue = new d6.default(function(e20, t15) {
      return t15.reqs - e20.reqs;
    }), t14.setupDequeueing();
  };
  var _s = Bs.prototype;
  var Ns = 0;
  var Is = Math.pow(2, 53) - 1;
  _s.makeLayer = function(e19, t14) {
    var n11 = Math.pow(2, t14), r8 = Math.ceil(e19.w * n11), a8 = Math.ceil(e19.h * n11), i9 = this.renderer.makeOffscreenCanvas(r8, a8), o11 = { id: Ns = ++Ns % Is, bb: e19, level: t14, width: r8, height: a8, canvas: i9, context: i9.getContext("2d"), eles: [], elesQueue: [], reqs: 0 }, s10 = o11.context, l10 = -o11.bb.x1, u9 = -o11.bb.y1;
    return s10.scale(n11, n11), s10.translate(l10, u9), o11;
  }, _s.getLayers = function(e19, t14, n11) {
    var r8 = this, a8 = r8.renderer.cy.zoom(), i9 = r8.firstGet;
    if (r8.firstGet = false, null == n11) {
      if ((n11 = Math.ceil(lt4(a8 * t14))) < -4)
        n11 = -4;
      else if (a8 >= 3.99 || n11 > 2)
        return null;
    }
    r8.validateLayersElesOrdering(n11, e19);
    var o11, s10, l10 = r8.layersByLevel, u9 = Math.pow(2, n11), c9 = l10[n11] = l10[n11] || [];
    if (r8.levelIsComplete(n11, e19))
      return c9;
    !function() {
      var t15 = function(t16) {
        if (r8.validateLayersElesOrdering(t16, e19), r8.levelIsComplete(t16, e19))
          return s10 = l10[t16], true;
      }, a9 = function(e20) {
        if (!s10)
          for (var r9 = n11 + e20; -4 <= r9 && r9 <= 2 && !t15(r9); r9 += e20)
            ;
      };
      a9(1), a9(-1);
      for (var i10 = c9.length - 1; i10 >= 0; i10--) {
        var o12 = c9[i10];
        o12.invalid && Le(c9, o12);
      }
    }();
    var d10 = function(t15) {
      var a9 = (t15 = t15 || {}).after;
      if (function() {
        if (!o11) {
          o11 = vt4();
          for (var t16 = 0; t16 < e19.length; t16++)
            n12 = o11, r9 = e19[t16].boundingBox(), n12.x1 = Math.min(n12.x1, r9.x1), n12.x2 = Math.max(n12.x2, r9.x2), n12.w = n12.x2 - n12.x1, n12.y1 = Math.min(n12.y1, r9.y1), n12.y2 = Math.max(n12.y2, r9.y2), n12.h = n12.y2 - n12.y1;
        }
        var n12, r9;
      }(), o11.w * u9 * (o11.h * u9) > 16e6)
        return null;
      var i10 = r8.makeLayer(o11, n11);
      if (null != a9) {
        var s11 = c9.indexOf(a9) + 1;
        c9.splice(s11, 0, i10);
      } else
        (void 0 === t15.insert || t15.insert) && c9.unshift(i10);
      return i10;
    };
    if (r8.skipping && !i9)
      return null;
    for (var h9 = null, p9 = e19.length / 1, f10 = !i9, g8 = 0; g8 < e19.length; g8++) {
      var v11 = e19[g8], y9 = v11._private.rscratch, m11 = y9.imgLayerCaches = y9.imgLayerCaches || {}, b10 = m11[n11];
      if (b10)
        h9 = b10;
      else {
        if ((!h9 || h9.eles.length >= p9 || !kt4(h9.bb, v11.boundingBox())) && !(h9 = d10({ insert: true, after: h9 })))
          return null;
        s10 || f10 ? r8.queueLayer(h9, v11) : r8.drawEleInLayer(h9, v11, n11, t14), h9.eles.push(v11), m11[n11] = h9;
      }
    }
    return s10 || (f10 ? null : c9);
  }, _s.getEleLevelForLayerLevel = function(e19, t14) {
    return e19;
  }, _s.drawEleInLayer = function(e19, t14, n11, r8) {
    var a8 = this.renderer, i9 = e19.context, o11 = t14.boundingBox();
    0 !== o11.w && 0 !== o11.h && t14.visible() && (n11 = this.getEleLevelForLayerLevel(n11, r8), a8.setImgSmoothing(i9, false), a8.drawCachedElement(i9, t14, null, null, n11, true), a8.setImgSmoothing(i9, true));
  }, _s.levelIsComplete = function(e19, t14) {
    var n11 = this.layersByLevel[e19];
    if (!n11 || 0 === n11.length)
      return false;
    for (var r8 = 0, a8 = 0; a8 < n11.length; a8++) {
      var i9 = n11[a8];
      if (i9.reqs > 0)
        return false;
      if (i9.invalid)
        return false;
      r8 += i9.eles.length;
    }
    return r8 === t14.length;
  }, _s.validateLayersElesOrdering = function(e19, t14) {
    var n11 = this.layersByLevel[e19];
    if (n11)
      for (var r8 = 0; r8 < n11.length; r8++) {
        for (var a8 = n11[r8], i9 = -1, o11 = 0; o11 < t14.length; o11++)
          if (a8.eles[0] === t14[o11]) {
            i9 = o11;
            break;
          }
        if (i9 < 0)
          this.invalidateLayer(a8);
        else {
          var s10 = i9;
          for (o11 = 0; o11 < a8.eles.length; o11++)
            if (a8.eles[o11] !== t14[s10 + o11]) {
              this.invalidateLayer(a8);
              break;
            }
        }
      }
  }, _s.updateElementsInLayers = function(e19, t14) {
    for (var n11 = A6(e19[0]), r8 = 0; r8 < e19.length; r8++)
      for (var a8 = n11 ? null : e19[r8], i9 = n11 ? e19[r8] : e19[r8].ele, o11 = i9._private.rscratch, s10 = o11.imgLayerCaches = o11.imgLayerCaches || {}, l10 = -4; l10 <= 2; l10++) {
        var u9 = s10[l10];
        u9 && (a8 && this.getEleLevelForLayerLevel(u9.level) !== a8.level || t14(u9, i9, a8));
      }
  }, _s.haveLayers = function() {
    for (var e19 = false, t14 = -4; t14 <= 2; t14++) {
      var n11 = this.layersByLevel[t14];
      if (n11 && n11.length > 0) {
        e19 = true;
        break;
      }
    }
    return e19;
  }, _s.invalidateElements = function(e19) {
    var t14 = this;
    0 !== e19.length && (t14.lastInvalidationTime = le(), 0 !== e19.length && t14.haveLayers() && t14.updateElementsInLayers(e19, function(e20, n11, r8) {
      t14.invalidateLayer(e20);
    }));
  }, _s.invalidateLayer = function(e19) {
    if (this.lastInvalidationTime = le(), !e19.invalid) {
      var t14 = e19.level, n11 = e19.eles, r8 = this.layersByLevel[t14];
      Le(r8, e19), e19.elesQueue = [], e19.invalid = true, e19.replacement && (e19.replacement.invalid = true);
      for (var a8 = 0; a8 < n11.length; a8++) {
        var i9 = n11[a8]._private.rscratch.imgLayerCaches;
        i9 && (i9[t14] = null);
      }
    }
  }, _s.refineElementTextures = function(e19) {
    var t14 = this;
    t14.updateElementsInLayers(e19, function(e20, n11, r8) {
      var a8 = e20.replacement;
      if (a8 || ((a8 = e20.replacement = t14.makeLayer(e20.bb, e20.level)).replaces = e20, a8.eles = e20.eles), !a8.reqs)
        for (var i9 = 0; i9 < a8.eles.length; i9++)
          t14.queueLayer(a8, a8.eles[i9]);
    });
  }, _s.enqueueElementRefinement = function(e19) {
    this.eleTxrDeqs.merge(e19), this.scheduleElementRefinement();
  }, _s.queueLayer = function(e19, t14) {
    var n11 = this.layersQueue, r8 = e19.elesQueue, a8 = r8.hasId = r8.hasId || {};
    if (!e19.replacement) {
      if (t14) {
        if (a8[t14.id()])
          return;
        r8.push(t14), a8[t14.id()] = true;
      }
      e19.reqs ? (e19.reqs++, n11.updateItem(e19)) : (e19.reqs = 1, n11.push(e19));
    }
  }, _s.dequeue = function(e19) {
    for (var t14 = this, n11 = t14.layersQueue, r8 = [], a8 = 0; a8 < 1 && 0 !== n11.size(); ) {
      var i9 = n11.peek();
      if (i9.replacement)
        n11.pop();
      else if (i9.replaces && i9 !== i9.replaces.replacement)
        n11.pop();
      else if (i9.invalid)
        n11.pop();
      else {
        var o11 = i9.elesQueue.shift();
        o11 && (t14.drawEleInLayer(i9, o11, i9.level, e19), a8++), 0 === r8.length && r8.push(true), 0 === i9.elesQueue.length && (n11.pop(), i9.reqs = 0, i9.replaces && t14.applyLayerReplacement(i9), t14.requestRedraw());
      }
    }
    return r8;
  }, _s.applyLayerReplacement = function(e19) {
    var t14 = this.layersByLevel[e19.level], n11 = e19.replaces, r8 = t14.indexOf(n11);
    if (!(r8 < 0 || n11.invalid)) {
      t14[r8] = e19;
      for (var a8 = 0; a8 < e19.eles.length; a8++) {
        var i9 = e19.eles[a8]._private, o11 = i9.imgLayerCaches = i9.imgLayerCaches || {};
        o11 && (o11[e19.level] = e19);
      }
      this.requestRedraw();
    }
  }, _s.requestRedraw = c6.default(function() {
    var e19 = this.renderer;
    e19.redrawHint("eles", true), e19.redrawHint("drag", true), e19.redraw();
  }, 100), _s.setupDequeueing = Cs({ deqRedrawThreshold: 50, deqCost: 0.15, deqAvgCost: 0.1, deqNoDrawCost: 0.9, deqFastCost: 0.9, deq: function(e19, t14) {
    return e19.dequeue(t14);
  }, onDeqd: De, shouldRedraw: ke, priority: function(e19) {
    return e19.renderer.beforeRenderPriorities.lyrTxrDeq;
  } });
  var zs;
  var Ls = {};
  function As(e19, t14) {
    for (var n11 = 0; n11 < t14.length; n11++) {
      var r8 = t14[n11];
      e19.lineTo(r8.x, r8.y);
    }
  }
  function Os(e19, t14, n11) {
    for (var r8, a8 = 0; a8 < t14.length; a8++) {
      var i9 = t14[a8];
      0 === a8 && (r8 = i9), e19.lineTo(i9.x, i9.y);
    }
    e19.quadraticCurveTo(n11.x, n11.y, r8.x, r8.y);
  }
  function Rs(e19, t14, n11) {
    e19.beginPath && e19.beginPath();
    for (var r8 = t14, a8 = 0; a8 < r8.length; a8++) {
      var i9 = r8[a8];
      e19.lineTo(i9.x, i9.y);
    }
    var o11 = n11, s10 = n11[0];
    e19.moveTo(s10.x, s10.y);
    for (a8 = 1; a8 < o11.length; a8++) {
      i9 = o11[a8];
      e19.lineTo(i9.x, i9.y);
    }
    e19.closePath && e19.closePath();
  }
  function Vs(e19, t14, n11, r8, a8) {
    e19.beginPath && e19.beginPath(), e19.arc(n11, r8, a8, 0, 2 * Math.PI, false);
    var i9 = t14, o11 = i9[0];
    e19.moveTo(o11.x, o11.y);
    for (var s10 = 0; s10 < i9.length; s10++) {
      var l10 = i9[s10];
      e19.lineTo(l10.x, l10.y);
    }
    e19.closePath && e19.closePath();
  }
  function Fs(e19, t14, n11, r8) {
    e19.arc(t14, n11, r8, 0, 2 * Math.PI, false);
  }
  Ls.arrowShapeImpl = function(e19) {
    return (zs || (zs = { polygon: As, "triangle-backcurve": Os, "triangle-tee": Rs, "circle-triangle": Vs, "triangle-cross": Rs, circle: Fs }))[e19];
  };
  var qs = { drawElement: function(e19, t14, n11, r8, a8, i9) {
    t14.isNode() ? this.drawNode(e19, t14, n11, r8, a8, i9) : this.drawEdge(e19, t14, n11, r8, a8, i9);
  }, drawElementOverlay: function(e19, t14) {
    t14.isNode() ? this.drawNodeOverlay(e19, t14) : this.drawEdgeOverlay(e19, t14);
  }, drawElementUnderlay: function(e19, t14) {
    t14.isNode() ? this.drawNodeUnderlay(e19, t14) : this.drawEdgeUnderlay(e19, t14);
  }, drawCachedElementPortion: function(e19, t14, n11, r8, a8, i9, o11, s10) {
    var l10 = this, u9 = n11.getBoundingBox(t14);
    if (0 !== u9.w && 0 !== u9.h) {
      var c9 = n11.getElement(t14, u9, r8, a8, i9);
      if (null != c9) {
        var d10 = s10(l10, t14);
        if (0 === d10)
          return;
        var h9, p9, f10, g8, v11, y9, m11 = o11(l10, t14), b10 = u9.x1, x10 = u9.y1, w9 = u9.w, E8 = u9.h;
        if (0 !== m11) {
          var k9 = n11.getRotationPoint(t14);
          f10 = k9.x, g8 = k9.y, e19.translate(f10, g8), e19.rotate(m11), (v11 = l10.getImgSmoothing(e19)) || l10.setImgSmoothing(e19, true);
          var C8 = n11.getRotationOffset(t14);
          h9 = C8.x, p9 = C8.y;
        } else
          h9 = b10, p9 = x10;
        1 !== d10 && (y9 = e19.globalAlpha, e19.globalAlpha = y9 * d10), e19.drawImage(c9.texture.canvas, c9.x, 0, c9.width, c9.height, h9, p9, w9, E8), 1 !== d10 && (e19.globalAlpha = y9), 0 !== m11 && (e19.rotate(-m11), e19.translate(-f10, -g8), v11 || l10.setImgSmoothing(e19, false));
      } else
        n11.drawElement(e19, t14);
    }
  } };
  var js = function() {
    return 0;
  };
  var Ys = function(e19, t14) {
    return e19.getTextAngle(t14, null);
  };
  var Xs = function(e19, t14) {
    return e19.getTextAngle(t14, "source");
  };
  var Ws = function(e19, t14) {
    return e19.getTextAngle(t14, "target");
  };
  var Hs = function(e19, t14) {
    return t14.effectiveOpacity();
  };
  var Ks = function(e19, t14) {
    return t14.pstyle("text-opacity").pfValue * t14.effectiveOpacity();
  };
  qs.drawCachedElement = function(e19, t14, n11, r8, a8, i9) {
    var o11 = this, s10 = o11.data, l10 = s10.eleTxrCache, u9 = s10.lblTxrCache, c9 = s10.slbTxrCache, d10 = s10.tlbTxrCache, h9 = t14.boundingBox(), p9 = true === i9 ? l10.reasons.highQuality : null;
    if (0 !== h9.w && 0 !== h9.h && t14.visible() && (!r8 || wt4(h9, r8))) {
      var f10 = t14.isEdge(), g8 = t14.element()._private.rscratch.badLine;
      o11.drawElementUnderlay(e19, t14), o11.drawCachedElementPortion(e19, t14, l10, n11, a8, p9, js, Hs), f10 && g8 || o11.drawCachedElementPortion(e19, t14, u9, n11, a8, p9, Ys, Ks), f10 && !g8 && (o11.drawCachedElementPortion(e19, t14, c9, n11, a8, p9, Xs, Ks), o11.drawCachedElementPortion(e19, t14, d10, n11, a8, p9, Ws, Ks)), o11.drawElementOverlay(e19, t14);
    }
  }, qs.drawElements = function(e19, t14) {
    for (var n11 = 0; n11 < t14.length; n11++) {
      var r8 = t14[n11];
      this.drawElement(e19, r8);
    }
  }, qs.drawCachedElements = function(e19, t14, n11, r8) {
    for (var a8 = 0; a8 < t14.length; a8++) {
      var i9 = t14[a8];
      this.drawCachedElement(e19, i9, n11, r8);
    }
  }, qs.drawCachedNodes = function(e19, t14, n11, r8) {
    for (var a8 = 0; a8 < t14.length; a8++) {
      var i9 = t14[a8];
      i9.isNode() && this.drawCachedElement(e19, i9, n11, r8);
    }
  }, qs.drawLayeredElements = function(e19, t14, n11, r8) {
    var a8 = this.data.lyrTxrCache.getLayers(t14, n11);
    if (a8)
      for (var i9 = 0; i9 < a8.length; i9++) {
        var o11 = a8[i9], s10 = o11.bb;
        0 !== s10.w && 0 !== s10.h && e19.drawImage(o11.canvas, s10.x1, s10.y1, s10.w, s10.h);
      }
    else
      this.drawCachedElements(e19, t14, n11, r8);
  };
  var Gs = { drawEdge: function(e19, t14, n11) {
    var r8 = !(arguments.length > 3 && void 0 !== arguments[3]) || arguments[3], a8 = !(arguments.length > 4 && void 0 !== arguments[4]) || arguments[4], i9 = !(arguments.length > 5 && void 0 !== arguments[5]) || arguments[5], o11 = this, s10 = t14._private.rscratch;
    if ((!i9 || t14.visible()) && !s10.badLine && null != s10.allpts && !isNaN(s10.allpts[0])) {
      var l10;
      n11 && (l10 = n11, e19.translate(-l10.x1, -l10.y1));
      var u9 = i9 ? t14.pstyle("opacity").value : 1, c9 = i9 ? t14.pstyle("line-opacity").value : 1, d10 = t14.pstyle("curve-style").value, h9 = t14.pstyle("line-style").value, p9 = t14.pstyle("width").pfValue, f10 = t14.pstyle("line-cap").value, g8 = u9 * c9, v11 = u9 * c9, y9 = function() {
        var n12 = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : g8;
        "straight-triangle" === d10 ? (o11.eleStrokeStyle(e19, t14, n12), o11.drawEdgeTrianglePath(t14, e19, s10.allpts)) : (e19.lineWidth = p9, e19.lineCap = f10, o11.eleStrokeStyle(e19, t14, n12), o11.drawEdgePath(t14, e19, s10.allpts, h9), e19.lineCap = "butt");
      }, m11 = function() {
        var n12 = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : v11;
        o11.drawArrowheads(e19, t14, n12);
      };
      if (e19.lineJoin = "round", "yes" === t14.pstyle("ghost").value) {
        var b10 = t14.pstyle("ghost-offset-x").pfValue, x10 = t14.pstyle("ghost-offset-y").pfValue, w9 = t14.pstyle("ghost-opacity").value, E8 = g8 * w9;
        e19.translate(b10, x10), y9(E8), m11(E8), e19.translate(-b10, -x10);
      }
      a8 && o11.drawEdgeUnderlay(e19, t14), y9(), m11(), a8 && o11.drawEdgeOverlay(e19, t14), o11.drawElementText(e19, t14, null, r8), n11 && e19.translate(l10.x1, l10.y1);
    }
  } };
  var Us = function(e19) {
    if (!["overlay", "underlay"].includes(e19))
      throw new Error("Invalid state");
    return function(t14, n11) {
      if (n11.visible()) {
        var r8 = n11.pstyle("".concat(e19, "-opacity")).value;
        if (0 !== r8) {
          var a8 = this, i9 = a8.usePaths(), o11 = n11._private.rscratch, s10 = 2 * n11.pstyle("".concat(e19, "-padding")).pfValue, l10 = n11.pstyle("".concat(e19, "-color")).value;
          t14.lineWidth = s10, "self" !== o11.edgeType || i9 ? t14.lineCap = "round" : t14.lineCap = "butt", a8.colorStrokeStyle(t14, l10[0], l10[1], l10[2], r8), a8.drawEdgePath(n11, t14, o11.allpts, "solid");
        }
      }
    };
  };
  Gs.drawEdgeOverlay = Us("overlay"), Gs.drawEdgeUnderlay = Us("underlay"), Gs.drawEdgePath = function(e19, t14, n11, r8) {
    var a8, i9 = e19._private.rscratch, o11 = t14, s10 = false, l10 = this.usePaths(), u9 = e19.pstyle("line-dash-pattern").pfValue, c9 = e19.pstyle("line-dash-offset").pfValue;
    if (l10) {
      var d10 = n11.join("$");
      i9.pathCacheKey && i9.pathCacheKey === d10 ? (a8 = t14 = i9.pathCache, s10 = true) : (a8 = t14 = new Path2D(), i9.pathCacheKey = d10, i9.pathCache = a8);
    }
    if (o11.setLineDash)
      switch (r8) {
        case "dotted":
          o11.setLineDash([1, 1]);
          break;
        case "dashed":
          o11.setLineDash(u9), o11.lineDashOffset = c9;
          break;
        case "solid":
          o11.setLineDash([]);
      }
    if (!s10 && !i9.badLine)
      switch (t14.beginPath && t14.beginPath(), t14.moveTo(n11[0], n11[1]), i9.edgeType) {
        case "bezier":
        case "self":
        case "compound":
        case "multibezier":
          for (var h9 = 2; h9 + 3 < n11.length; h9 += 4)
            t14.quadraticCurveTo(n11[h9], n11[h9 + 1], n11[h9 + 2], n11[h9 + 3]);
          break;
        case "straight":
        case "segments":
        case "haystack":
          for (var p9 = 2; p9 + 1 < n11.length; p9 += 2)
            t14.lineTo(n11[p9], n11[p9 + 1]);
      }
    t14 = o11, l10 ? t14.stroke(a8) : t14.stroke(), t14.setLineDash && t14.setLineDash([]);
  }, Gs.drawEdgeTrianglePath = function(e19, t14, n11) {
    t14.fillStyle = t14.strokeStyle;
    for (var r8 = e19.pstyle("width").pfValue, a8 = 0; a8 + 1 < n11.length; a8 += 2) {
      var i9 = [n11[a8 + 2] - n11[a8], n11[a8 + 3] - n11[a8 + 1]], o11 = Math.sqrt(i9[0] * i9[0] + i9[1] * i9[1]), s10 = [i9[1] / o11, -i9[0] / o11], l10 = [s10[0] * r8 / 2, s10[1] * r8 / 2];
      t14.beginPath(), t14.moveTo(n11[a8] - l10[0], n11[a8 + 1] - l10[1]), t14.lineTo(n11[a8] + l10[0], n11[a8 + 1] + l10[1]), t14.lineTo(n11[a8 + 2], n11[a8 + 3]), t14.closePath(), t14.fill();
    }
  }, Gs.drawArrowheads = function(e19, t14, n11) {
    var r8 = t14._private.rscratch, a8 = "haystack" === r8.edgeType;
    a8 || this.drawArrowhead(e19, t14, "source", r8.arrowStartX, r8.arrowStartY, r8.srcArrowAngle, n11), this.drawArrowhead(e19, t14, "mid-target", r8.midX, r8.midY, r8.midtgtArrowAngle, n11), this.drawArrowhead(e19, t14, "mid-source", r8.midX, r8.midY, r8.midsrcArrowAngle, n11), a8 || this.drawArrowhead(e19, t14, "target", r8.arrowEndX, r8.arrowEndY, r8.tgtArrowAngle, n11);
  }, Gs.drawArrowhead = function(e19, t14, n11, r8, a8, i9, o11) {
    if (!(isNaN(r8) || null == r8 || isNaN(a8) || null == a8 || isNaN(i9) || null == i9)) {
      var s10 = this, l10 = t14.pstyle(n11 + "-arrow-shape").value;
      if ("none" !== l10) {
        var u9 = "hollow" === t14.pstyle(n11 + "-arrow-fill").value ? "both" : "filled", c9 = t14.pstyle(n11 + "-arrow-fill").value, d10 = t14.pstyle("width").pfValue, h9 = t14.pstyle("opacity").value;
        void 0 === o11 && (o11 = h9);
        var p9 = e19.globalCompositeOperation;
        1 === o11 && "hollow" !== c9 || (e19.globalCompositeOperation = "destination-out", s10.colorFillStyle(e19, 255, 255, 255, 1), s10.colorStrokeStyle(e19, 255, 255, 255, 1), s10.drawArrowShape(t14, e19, u9, d10, l10, r8, a8, i9), e19.globalCompositeOperation = p9);
        var f10 = t14.pstyle(n11 + "-arrow-color").value;
        s10.colorFillStyle(e19, f10[0], f10[1], f10[2], o11), s10.colorStrokeStyle(e19, f10[0], f10[1], f10[2], o11), s10.drawArrowShape(t14, e19, c9, d10, l10, r8, a8, i9);
      }
    }
  }, Gs.drawArrowShape = function(e19, t14, n11, r8, a8, i9, o11, s10) {
    var l10, u9 = this, c9 = this.usePaths() && "triangle-cross" !== a8, d10 = false, h9 = t14, p9 = { x: i9, y: o11 }, f10 = e19.pstyle("arrow-scale").value, g8 = this.getArrowWidth(r8, f10), v11 = u9.arrowShapes[a8];
    if (c9) {
      var y9 = u9.arrowPathCache = u9.arrowPathCache || [], m11 = ve(a8), b10 = y9[m11];
      null != b10 ? (l10 = t14 = b10, d10 = true) : (l10 = t14 = new Path2D(), y9[m11] = l10);
    }
    d10 || (t14.beginPath && t14.beginPath(), c9 ? v11.draw(t14, 1, 0, { x: 0, y: 0 }, 1) : v11.draw(t14, g8, s10, p9, r8), t14.closePath && t14.closePath()), t14 = h9, c9 && (t14.translate(i9, o11), t14.rotate(s10), t14.scale(g8, g8)), "filled" !== n11 && "both" !== n11 || (c9 ? t14.fill(l10) : t14.fill()), "hollow" !== n11 && "both" !== n11 || (t14.lineWidth = (v11.matchEdgeWidth ? r8 : 1) / (c9 ? g8 : 1), t14.lineJoin = "miter", c9 ? t14.stroke(l10) : t14.stroke()), c9 && (t14.scale(1 / g8, 1 / g8), t14.rotate(-s10), t14.translate(-i9, -o11));
  };
  var Zs = { safeDrawImage: function(e19, t14, n11, r8, a8, i9, o11, s10, l10, u9) {
    if (!(a8 <= 0 || i9 <= 0 || l10 <= 0 || u9 <= 0))
      try {
        e19.drawImage(t14, n11, r8, a8, i9, o11, s10, l10, u9);
      } catch (e20) {
        Me(e20);
      }
  }, drawInscribedImage: function(e19, t14, n11, r8, a8) {
    var i9 = this, o11 = n11.position(), s10 = o11.x, l10 = o11.y, u9 = n11.cy().style(), c9 = u9.getIndexedStyle.bind(u9), d10 = c9(n11, "background-fit", "value", r8), h9 = c9(n11, "background-repeat", "value", r8), p9 = n11.width(), f10 = n11.height(), g8 = 2 * n11.padding(), v11 = p9 + ("inner" === c9(n11, "background-width-relative-to", "value", r8) ? 0 : g8), y9 = f10 + ("inner" === c9(n11, "background-height-relative-to", "value", r8) ? 0 : g8), m11 = n11._private.rscratch, b10 = "node" === c9(n11, "background-clip", "value", r8), x10 = c9(n11, "background-image-opacity", "value", r8) * a8, w9 = c9(n11, "background-image-smoothing", "value", r8), E8 = t14.width || t14.cachedW, k9 = t14.height || t14.cachedH;
    null != E8 && null != k9 || (document.body.appendChild(t14), E8 = t14.cachedW = t14.width || t14.offsetWidth, k9 = t14.cachedH = t14.height || t14.offsetHeight, document.body.removeChild(t14));
    var C8 = E8, S7 = k9;
    if ("auto" !== c9(n11, "background-width", "value", r8) && (C8 = "%" === c9(n11, "background-width", "units", r8) ? c9(n11, "background-width", "pfValue", r8) * v11 : c9(n11, "background-width", "pfValue", r8)), "auto" !== c9(n11, "background-height", "value", r8) && (S7 = "%" === c9(n11, "background-height", "units", r8) ? c9(n11, "background-height", "pfValue", r8) * y9 : c9(n11, "background-height", "pfValue", r8)), 0 !== C8 && 0 !== S7) {
      if ("contain" === d10)
        C8 *= D7 = Math.min(v11 / C8, y9 / S7), S7 *= D7;
      else if ("cover" === d10) {
        var D7;
        C8 *= D7 = Math.max(v11 / C8, y9 / S7), S7 *= D7;
      }
      var P9 = s10 - v11 / 2, T8 = c9(n11, "background-position-x", "units", r8), M8 = c9(n11, "background-position-x", "pfValue", r8);
      P9 += "%" === T8 ? (v11 - C8) * M8 : M8;
      var B8 = c9(n11, "background-offset-x", "units", r8), _6 = c9(n11, "background-offset-x", "pfValue", r8);
      P9 += "%" === B8 ? (v11 - C8) * _6 : _6;
      var N7 = l10 - y9 / 2, I7 = c9(n11, "background-position-y", "units", r8), z7 = c9(n11, "background-position-y", "pfValue", r8);
      N7 += "%" === I7 ? (y9 - S7) * z7 : z7;
      var L9 = c9(n11, "background-offset-y", "units", r8), A9 = c9(n11, "background-offset-y", "pfValue", r8);
      N7 += "%" === L9 ? (y9 - S7) * A9 : A9, m11.pathCache && (P9 -= s10, N7 -= l10, s10 = 0, l10 = 0);
      var O8 = e19.globalAlpha;
      e19.globalAlpha = x10;
      var R7 = i9.getImgSmoothing(e19), V6 = false;
      if ("no" === w9 && R7 ? (i9.setImgSmoothing(e19, false), V6 = true) : "yes" !== w9 || R7 || (i9.setImgSmoothing(e19, true), V6 = true), "no-repeat" === h9)
        b10 && (e19.save(), m11.pathCache ? e19.clip(m11.pathCache) : (i9.nodeShapes[i9.getNodeShape(n11)].draw(e19, s10, l10, v11, y9), e19.clip())), i9.safeDrawImage(e19, t14, 0, 0, E8, k9, P9, N7, C8, S7), b10 && e19.restore();
      else {
        var F7 = e19.createPattern(t14, h9);
        e19.fillStyle = F7, i9.nodeShapes[i9.getNodeShape(n11)].draw(e19, s10, l10, v11, y9), e19.translate(P9, N7), e19.fill(), e19.translate(-P9, -N7);
      }
      e19.globalAlpha = O8, V6 && i9.setImgSmoothing(e19, R7);
    }
  } };
  var $s = {};
  $s.eleTextBiggerThanMin = function(e19, t14) {
    if (!t14) {
      var n11 = e19.cy().zoom(), r8 = this.getPixelRatio(), a8 = Math.ceil(lt4(n11 * r8));
      t14 = Math.pow(2, a8);
    }
    return !(e19.pstyle("font-size").pfValue * t14 < e19.pstyle("min-zoomed-font-size").pfValue);
  }, $s.drawElementText = function(e19, t14, n11, r8, a8) {
    var i9 = !(arguments.length > 5 && void 0 !== arguments[5]) || arguments[5], o11 = this;
    if (null == r8) {
      if (i9 && !o11.eleTextBiggerThanMin(t14))
        return;
    } else if (false === r8)
      return;
    if (t14.isNode()) {
      var s10 = t14.pstyle("label");
      if (!s10 || !s10.value)
        return;
      var l10 = o11.getLabelJustification(t14);
      e19.textAlign = l10, e19.textBaseline = "bottom";
    } else {
      var u9 = t14.element()._private.rscratch.badLine, c9 = t14.pstyle("label"), d10 = t14.pstyle("source-label"), h9 = t14.pstyle("target-label");
      if (u9 || (!c9 || !c9.value) && (!d10 || !d10.value) && (!h9 || !h9.value))
        return;
      e19.textAlign = "center", e19.textBaseline = "bottom";
    }
    var p9, f10 = !n11;
    n11 && (p9 = n11, e19.translate(-p9.x1, -p9.y1)), null == a8 ? (o11.drawText(e19, t14, null, f10, i9), t14.isEdge() && (o11.drawText(e19, t14, "source", f10, i9), o11.drawText(e19, t14, "target", f10, i9))) : o11.drawText(e19, t14, a8, f10, i9), n11 && e19.translate(p9.x1, p9.y1);
  }, $s.getFontCache = function(e19) {
    var t14;
    this.fontCaches = this.fontCaches || [];
    for (var n11 = 0; n11 < this.fontCaches.length; n11++)
      if ((t14 = this.fontCaches[n11]).context === e19)
        return t14;
    return t14 = { context: e19 }, this.fontCaches.push(t14), t14;
  }, $s.setupTextStyle = function(e19, t14) {
    var n11 = !(arguments.length > 2 && void 0 !== arguments[2]) || arguments[2], r8 = t14.pstyle("font-style").strValue, a8 = t14.pstyle("font-size").pfValue + "px", i9 = t14.pstyle("font-family").strValue, o11 = t14.pstyle("font-weight").strValue, s10 = n11 ? t14.effectiveOpacity() * t14.pstyle("text-opacity").value : 1, l10 = t14.pstyle("text-outline-opacity").value * s10, u9 = t14.pstyle("color").value, c9 = t14.pstyle("text-outline-color").value;
    e19.font = r8 + " " + o11 + " " + a8 + " " + i9, e19.lineJoin = "round", this.colorFillStyle(e19, u9[0], u9[1], u9[2], s10), this.colorStrokeStyle(e19, c9[0], c9[1], c9[2], l10);
  }, $s.getTextAngle = function(e19, t14) {
    var n11 = e19._private.rscratch, r8 = t14 ? t14 + "-" : "", a8 = e19.pstyle(r8 + "text-rotation"), i9 = Oe(n11, "labelAngle", t14);
    return "autorotate" === a8.strValue ? e19.isEdge() ? i9 : 0 : "none" === a8.strValue ? 0 : a8.pfValue;
  }, $s.drawText = function(e19, t14, n11) {
    var r8 = !(arguments.length > 3 && void 0 !== arguments[3]) || arguments[3], a8 = !(arguments.length > 4 && void 0 !== arguments[4]) || arguments[4], i9 = t14._private.rscratch, o11 = a8 ? t14.effectiveOpacity() : 1;
    if (!a8 || 0 !== o11 && 0 !== t14.pstyle("text-opacity").value) {
      "main" === n11 && (n11 = null);
      var s10, l10, u9 = Oe(i9, "labelX", n11), c9 = Oe(i9, "labelY", n11), d10 = this.getLabelText(t14, n11);
      if (null != d10 && "" !== d10 && !isNaN(u9) && !isNaN(c9)) {
        this.setupTextStyle(e19, t14, a8);
        var h9, p9 = n11 ? n11 + "-" : "", f10 = Oe(i9, "labelWidth", n11), g8 = Oe(i9, "labelHeight", n11), v11 = t14.pstyle(p9 + "text-margin-x").pfValue, y9 = t14.pstyle(p9 + "text-margin-y").pfValue, m11 = t14.isEdge(), b10 = t14.pstyle("text-halign").value, x10 = t14.pstyle("text-valign").value;
        switch (m11 && (b10 = "center", x10 = "center"), u9 += v11, c9 += y9, 0 !== (h9 = r8 ? this.getTextAngle(t14, n11) : 0) && (s10 = u9, l10 = c9, e19.translate(s10, l10), e19.rotate(h9), u9 = 0, c9 = 0), x10) {
          case "top":
            break;
          case "center":
            c9 += g8 / 2;
            break;
          case "bottom":
            c9 += g8;
        }
        var w9 = t14.pstyle("text-background-opacity").value, E8 = t14.pstyle("text-border-opacity").value, k9 = t14.pstyle("text-border-width").pfValue, C8 = t14.pstyle("text-background-padding").pfValue;
        if (w9 > 0 || k9 > 0 && E8 > 0) {
          var S7 = u9 - C8;
          switch (b10) {
            case "left":
              S7 -= f10;
              break;
            case "center":
              S7 -= f10 / 2;
          }
          var D7 = c9 - g8 - C8, P9 = f10 + 2 * C8, T8 = g8 + 2 * C8;
          if (w9 > 0) {
            var M8 = e19.fillStyle, B8 = t14.pstyle("text-background-color").value;
            e19.fillStyle = "rgba(" + B8[0] + "," + B8[1] + "," + B8[2] + "," + w9 * o11 + ")", 0 === t14.pstyle("text-background-shape").strValue.indexOf("round") ? function(e20, t15, n12, r9, a9) {
              var i10 = arguments.length > 5 && void 0 !== arguments[5] ? arguments[5] : 5;
              e20.beginPath(), e20.moveTo(t15 + i10, n12), e20.lineTo(t15 + r9 - i10, n12), e20.quadraticCurveTo(t15 + r9, n12, t15 + r9, n12 + i10), e20.lineTo(t15 + r9, n12 + a9 - i10), e20.quadraticCurveTo(t15 + r9, n12 + a9, t15 + r9 - i10, n12 + a9), e20.lineTo(t15 + i10, n12 + a9), e20.quadraticCurveTo(t15, n12 + a9, t15, n12 + a9 - i10), e20.lineTo(t15, n12 + i10), e20.quadraticCurveTo(t15, n12, t15 + i10, n12), e20.closePath(), e20.fill();
            }(e19, S7, D7, P9, T8, 2) : e19.fillRect(S7, D7, P9, T8), e19.fillStyle = M8;
          }
          if (k9 > 0 && E8 > 0) {
            var _6 = e19.strokeStyle, N7 = e19.lineWidth, I7 = t14.pstyle("text-border-color").value, z7 = t14.pstyle("text-border-style").value;
            if (e19.strokeStyle = "rgba(" + I7[0] + "," + I7[1] + "," + I7[2] + "," + E8 * o11 + ")", e19.lineWidth = k9, e19.setLineDash)
              switch (z7) {
                case "dotted":
                  e19.setLineDash([1, 1]);
                  break;
                case "dashed":
                  e19.setLineDash([4, 2]);
                  break;
                case "double":
                  e19.lineWidth = k9 / 4, e19.setLineDash([]);
                  break;
                case "solid":
                  e19.setLineDash([]);
              }
            if (e19.strokeRect(S7, D7, P9, T8), "double" === z7) {
              var L9 = k9 / 2;
              e19.strokeRect(S7 + L9, D7 + L9, P9 - 2 * L9, T8 - 2 * L9);
            }
            e19.setLineDash && e19.setLineDash([]), e19.lineWidth = N7, e19.strokeStyle = _6;
          }
        }
        var A9 = 2 * t14.pstyle("text-outline-width").pfValue;
        if (A9 > 0 && (e19.lineWidth = A9), "wrap" === t14.pstyle("text-wrap").value) {
          var O8 = Oe(i9, "labelWrapCachedLines", n11), R7 = Oe(i9, "labelLineHeight", n11), V6 = f10 / 2, F7 = this.getLabelJustification(t14);
          switch ("auto" === F7 || ("left" === b10 ? "left" === F7 ? u9 += -f10 : "center" === F7 && (u9 += -V6) : "center" === b10 ? "left" === F7 ? u9 += -V6 : "right" === F7 && (u9 += V6) : "right" === b10 && ("center" === F7 ? u9 += V6 : "right" === F7 && (u9 += f10))), x10) {
            case "top":
            case "center":
            case "bottom":
              c9 -= (O8.length - 1) * R7;
          }
          for (var q7 = 0; q7 < O8.length; q7++)
            A9 > 0 && e19.strokeText(O8[q7], u9, c9), e19.fillText(O8[q7], u9, c9), c9 += R7;
        } else
          A9 > 0 && e19.strokeText(d10, u9, c9), e19.fillText(d10, u9, c9);
        0 !== h9 && (e19.rotate(-h9), e19.translate(-s10, -l10));
      }
    }
  };
  var Qs = { drawNode: function(e19, t14, n11) {
    var r8, a8, i9 = !(arguments.length > 3 && void 0 !== arguments[3]) || arguments[3], o11 = !(arguments.length > 4 && void 0 !== arguments[4]) || arguments[4], s10 = !(arguments.length > 5 && void 0 !== arguments[5]) || arguments[5], l10 = this, u9 = t14._private, c9 = u9.rscratch, d10 = t14.position();
    if (I6(d10.x) && I6(d10.y) && (!s10 || t14.visible())) {
      var h9, p9, f10 = s10 ? t14.effectiveOpacity() : 1, g8 = l10.usePaths(), v11 = false, y9 = t14.padding();
      r8 = t14.width() + 2 * y9, a8 = t14.height() + 2 * y9, n11 && (p9 = n11, e19.translate(-p9.x1, -p9.y1));
      for (var m11 = t14.pstyle("background-image").value, b10 = new Array(m11.length), x10 = new Array(m11.length), w9 = 0, E8 = 0; E8 < m11.length; E8++) {
        var k9 = m11[E8];
        if (b10[E8] = null != k9 && "none" !== k9) {
          var C8 = t14.cy().style().getIndexedStyle(t14, "background-image-crossorigin", "value", E8);
          w9++, x10[E8] = l10.getCachedImage(k9, C8, function() {
            u9.backgroundTimestamp = Date.now(), t14.emitAndNotify("background");
          });
        }
      }
      var S7 = t14.pstyle("background-blacken").value, D7 = t14.pstyle("border-width").pfValue, P9 = t14.pstyle("background-opacity").value * f10, T8 = t14.pstyle("border-color").value, M8 = t14.pstyle("border-style").value, B8 = t14.pstyle("border-opacity").value * f10;
      e19.lineJoin = "miter";
      var _6 = function() {
        var n12 = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : P9;
        l10.eleFillStyle(e19, t14, n12);
      }, N7 = function() {
        var t15 = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : B8;
        l10.colorStrokeStyle(e19, T8[0], T8[1], T8[2], t15);
      }, z7 = t14.pstyle("shape").strValue, L9 = t14.pstyle("shape-polygon-points").pfValue;
      if (g8) {
        e19.translate(d10.x, d10.y);
        var A9 = l10.nodePathCache = l10.nodePathCache || [], O8 = ye("polygon" === z7 ? z7 + "," + L9.join(",") : z7, "" + a8, "" + r8), R7 = A9[O8];
        null != R7 ? (h9 = R7, v11 = true, c9.pathCache = h9) : (h9 = new Path2D(), A9[O8] = c9.pathCache = h9);
      }
      var V6 = function() {
        if (!v11) {
          var n12 = d10;
          g8 && (n12 = { x: 0, y: 0 }), l10.nodeShapes[l10.getNodeShape(t14)].draw(h9 || e19, n12.x, n12.y, r8, a8);
        }
        g8 ? e19.fill(h9) : e19.fill();
      }, F7 = function() {
        for (var n12 = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : f10, r9 = !(arguments.length > 1 && void 0 !== arguments[1]) || arguments[1], a9 = u9.backgrounding, i10 = 0, o12 = 0; o12 < x10.length; o12++) {
          var s11 = t14.cy().style().getIndexedStyle(t14, "background-image-containment", "value", o12);
          r9 && "over" === s11 || !r9 && "inside" === s11 ? i10++ : b10[o12] && x10[o12].complete && !x10[o12].error && (i10++, l10.drawInscribedImage(e19, x10[o12], t14, o12, n12));
        }
        u9.backgrounding = !(i10 === w9), a9 !== u9.backgrounding && t14.updateStyle(false);
      }, q7 = function() {
        var n12 = arguments.length > 0 && void 0 !== arguments[0] && arguments[0], i10 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : f10;
        l10.hasPie(t14) && (l10.drawPie(e19, t14, i10), n12 && (g8 || l10.nodeShapes[l10.getNodeShape(t14)].draw(e19, d10.x, d10.y, r8, a8)));
      }, j8 = function() {
        var t15 = (S7 > 0 ? S7 : -S7) * (arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : f10), n12 = S7 > 0 ? 0 : 255;
        0 !== S7 && (l10.colorFillStyle(e19, n12, n12, n12, t15), g8 ? e19.fill(h9) : e19.fill());
      }, Y5 = function() {
        if (D7 > 0) {
          if (e19.lineWidth = D7, e19.lineCap = "butt", e19.setLineDash)
            switch (M8) {
              case "dotted":
                e19.setLineDash([1, 1]);
                break;
              case "dashed":
                e19.setLineDash([4, 2]);
                break;
              case "solid":
              case "double":
                e19.setLineDash([]);
            }
          if (g8 ? e19.stroke(h9) : e19.stroke(), "double" === M8) {
            e19.lineWidth = D7 / 3;
            var t15 = e19.globalCompositeOperation;
            e19.globalCompositeOperation = "destination-out", g8 ? e19.stroke(h9) : e19.stroke(), e19.globalCompositeOperation = t15;
          }
          e19.setLineDash && e19.setLineDash([]);
        }
      };
      if ("yes" === t14.pstyle("ghost").value) {
        var X5 = t14.pstyle("ghost-offset-x").pfValue, W7 = t14.pstyle("ghost-offset-y").pfValue, H8 = t14.pstyle("ghost-opacity").value, K5 = H8 * f10;
        e19.translate(X5, W7), _6(H8 * P9), V6(), F7(K5, true), N7(H8 * B8), Y5(), q7(0 !== S7 || 0 !== D7), F7(K5, false), j8(K5), e19.translate(-X5, -W7);
      }
      g8 && e19.translate(-d10.x, -d10.y), o11 && l10.drawNodeUnderlay(e19, t14, d10, r8, a8), g8 && e19.translate(d10.x, d10.y), _6(), V6(), F7(f10, true), N7(), Y5(), q7(0 !== S7 || 0 !== D7), F7(f10, false), j8(), g8 && e19.translate(-d10.x, -d10.y), l10.drawElementText(e19, t14, null, i9), o11 && l10.drawNodeOverlay(e19, t14, d10, r8, a8), n11 && e19.translate(p9.x1, p9.y1);
    }
  } };
  var Js = function(e19) {
    if (!["overlay", "underlay"].includes(e19))
      throw new Error("Invalid state");
    return function(t14, n11, r8, a8, i9) {
      if (n11.visible()) {
        var o11 = n11.pstyle("".concat(e19, "-padding")).pfValue, s10 = n11.pstyle("".concat(e19, "-opacity")).value, l10 = n11.pstyle("".concat(e19, "-color")).value, u9 = n11.pstyle("".concat(e19, "-shape")).value;
        if (s10 > 0) {
          if (r8 = r8 || n11.position(), null == a8 || null == i9) {
            var c9 = n11.padding();
            a8 = n11.width() + 2 * c9, i9 = n11.height() + 2 * c9;
          }
          this.colorFillStyle(t14, l10[0], l10[1], l10[2], s10), this.nodeShapes[u9].draw(t14, r8.x, r8.y, a8 + 2 * o11, i9 + 2 * o11), t14.fill();
        }
      }
    };
  };
  Qs.drawNodeOverlay = Js("overlay"), Qs.drawNodeUnderlay = Js("underlay"), Qs.hasPie = function(e19) {
    return (e19 = e19[0])._private.hasPie;
  }, Qs.drawPie = function(e19, t14, n11, r8) {
    t14 = t14[0], r8 = r8 || t14.position();
    var a8 = t14.cy().style(), i9 = t14.pstyle("pie-size"), o11 = r8.x, s10 = r8.y, l10 = t14.width(), u9 = t14.height(), c9 = Math.min(l10, u9) / 2, d10 = 0;
    this.usePaths() && (o11 = 0, s10 = 0), "%" === i9.units ? c9 *= i9.pfValue : void 0 !== i9.pfValue && (c9 = i9.pfValue / 2);
    for (var h9 = 1; h9 <= a8.pieBackgroundN; h9++) {
      var p9 = t14.pstyle("pie-" + h9 + "-background-size").value, f10 = t14.pstyle("pie-" + h9 + "-background-color").value, g8 = t14.pstyle("pie-" + h9 + "-background-opacity").value * n11, v11 = p9 / 100;
      v11 + d10 > 1 && (v11 = 1 - d10);
      var y9 = 1.5 * Math.PI + 2 * Math.PI * d10, m11 = y9 + 2 * Math.PI * v11;
      0 === p9 || d10 >= 1 || d10 + v11 > 1 || (e19.beginPath(), e19.moveTo(o11, s10), e19.arc(o11, s10, c9, y9, m11), e19.closePath(), this.colorFillStyle(e19, f10[0], f10[1], f10[2], g8), e19.fill(), d10 += v11);
    }
  };
  var el = {};
  el.getPixelRatio = function() {
    var e19 = this.data.contexts[0];
    if (null != this.forcedPixelRatio)
      return this.forcedPixelRatio;
    var t14 = e19.backingStorePixelRatio || e19.webkitBackingStorePixelRatio || e19.mozBackingStorePixelRatio || e19.msBackingStorePixelRatio || e19.oBackingStorePixelRatio || e19.backingStorePixelRatio || 1;
    return (window.devicePixelRatio || 1) / t14;
  }, el.paintCache = function(e19) {
    for (var t14, n11 = this.paintCaches = this.paintCaches || [], r8 = true, a8 = 0; a8 < n11.length; a8++)
      if ((t14 = n11[a8]).context === e19) {
        r8 = false;
        break;
      }
    return r8 && (t14 = { context: e19 }, n11.push(t14)), t14;
  }, el.createGradientStyleFor = function(e19, t14, n11, r8, a8) {
    var i9, o11 = this.usePaths(), s10 = n11.pstyle(t14 + "-gradient-stop-colors").value, l10 = n11.pstyle(t14 + "-gradient-stop-positions").pfValue;
    if ("radial-gradient" === r8)
      if (n11.isEdge()) {
        var u9 = n11.sourceEndpoint(), c9 = n11.targetEndpoint(), d10 = n11.midpoint(), h9 = ct4(u9, d10), p9 = ct4(c9, d10);
        i9 = e19.createRadialGradient(d10.x, d10.y, 0, d10.x, d10.y, Math.max(h9, p9));
      } else {
        var f10 = o11 ? { x: 0, y: 0 } : n11.position(), g8 = n11.paddedWidth(), v11 = n11.paddedHeight();
        i9 = e19.createRadialGradient(f10.x, f10.y, 0, f10.x, f10.y, Math.max(g8, v11));
      }
    else if (n11.isEdge()) {
      var y9 = n11.sourceEndpoint(), m11 = n11.targetEndpoint();
      i9 = e19.createLinearGradient(y9.x, y9.y, m11.x, m11.y);
    } else {
      var b10 = o11 ? { x: 0, y: 0 } : n11.position(), x10 = n11.paddedWidth() / 2, w9 = n11.paddedHeight() / 2;
      switch (n11.pstyle("background-gradient-direction").value) {
        case "to-bottom":
          i9 = e19.createLinearGradient(b10.x, b10.y - w9, b10.x, b10.y + w9);
          break;
        case "to-top":
          i9 = e19.createLinearGradient(b10.x, b10.y + w9, b10.x, b10.y - w9);
          break;
        case "to-left":
          i9 = e19.createLinearGradient(b10.x + x10, b10.y, b10.x - x10, b10.y);
          break;
        case "to-right":
          i9 = e19.createLinearGradient(b10.x - x10, b10.y, b10.x + x10, b10.y);
          break;
        case "to-bottom-right":
        case "to-right-bottom":
          i9 = e19.createLinearGradient(b10.x - x10, b10.y - w9, b10.x + x10, b10.y + w9);
          break;
        case "to-top-right":
        case "to-right-top":
          i9 = e19.createLinearGradient(b10.x - x10, b10.y + w9, b10.x + x10, b10.y - w9);
          break;
        case "to-bottom-left":
        case "to-left-bottom":
          i9 = e19.createLinearGradient(b10.x + x10, b10.y - w9, b10.x - x10, b10.y + w9);
          break;
        case "to-top-left":
        case "to-left-top":
          i9 = e19.createLinearGradient(b10.x + x10, b10.y + w9, b10.x - x10, b10.y - w9);
      }
    }
    if (!i9)
      return null;
    for (var E8 = l10.length === s10.length, k9 = s10.length, C8 = 0; C8 < k9; C8++)
      i9.addColorStop(E8 ? l10[C8] : C8 / (k9 - 1), "rgba(" + s10[C8][0] + "," + s10[C8][1] + "," + s10[C8][2] + "," + a8 + ")");
    return i9;
  }, el.gradientFillStyle = function(e19, t14, n11, r8) {
    var a8 = this.createGradientStyleFor(e19, "background", t14, n11, r8);
    if (!a8)
      return null;
    e19.fillStyle = a8;
  }, el.colorFillStyle = function(e19, t14, n11, r8, a8) {
    e19.fillStyle = "rgba(" + t14 + "," + n11 + "," + r8 + "," + a8 + ")";
  }, el.eleFillStyle = function(e19, t14, n11) {
    var r8 = t14.pstyle("background-fill").value;
    if ("linear-gradient" === r8 || "radial-gradient" === r8)
      this.gradientFillStyle(e19, t14, r8, n11);
    else {
      var a8 = t14.pstyle("background-color").value;
      this.colorFillStyle(e19, a8[0], a8[1], a8[2], n11);
    }
  }, el.gradientStrokeStyle = function(e19, t14, n11, r8) {
    var a8 = this.createGradientStyleFor(e19, "line", t14, n11, r8);
    if (!a8)
      return null;
    e19.strokeStyle = a8;
  }, el.colorStrokeStyle = function(e19, t14, n11, r8, a8) {
    e19.strokeStyle = "rgba(" + t14 + "," + n11 + "," + r8 + "," + a8 + ")";
  }, el.eleStrokeStyle = function(e19, t14, n11) {
    var r8 = t14.pstyle("line-fill").value;
    if ("linear-gradient" === r8 || "radial-gradient" === r8)
      this.gradientStrokeStyle(e19, t14, r8, n11);
    else {
      var a8 = t14.pstyle("line-color").value;
      this.colorStrokeStyle(e19, a8[0], a8[1], a8[2], n11);
    }
  }, el.matchCanvasSize = function(e19) {
    var t14 = this, n11 = t14.data, r8 = t14.findContainerClientCoords(), a8 = r8[2], i9 = r8[3], o11 = t14.getPixelRatio(), s10 = t14.motionBlurPxRatio;
    e19 !== t14.data.bufferCanvases[t14.MOTIONBLUR_BUFFER_NODE] && e19 !== t14.data.bufferCanvases[t14.MOTIONBLUR_BUFFER_DRAG] || (o11 = s10);
    var l10, u9 = a8 * o11, c9 = i9 * o11;
    if (u9 !== t14.canvasWidth || c9 !== t14.canvasHeight) {
      t14.fontCaches = null;
      var d10 = n11.canvasContainer;
      d10.style.width = a8 + "px", d10.style.height = i9 + "px";
      for (var h9 = 0; h9 < t14.CANVAS_LAYERS; h9++)
        (l10 = n11.canvases[h9]).width = u9, l10.height = c9, l10.style.width = a8 + "px", l10.style.height = i9 + "px";
      for (h9 = 0; h9 < t14.BUFFER_COUNT; h9++)
        (l10 = n11.bufferCanvases[h9]).width = u9, l10.height = c9, l10.style.width = a8 + "px", l10.style.height = i9 + "px";
      t14.textureMult = 1, o11 <= 1 && (l10 = n11.bufferCanvases[t14.TEXTURE_BUFFER], t14.textureMult = 2, l10.width = u9 * t14.textureMult, l10.height = c9 * t14.textureMult), t14.canvasWidth = u9, t14.canvasHeight = c9;
    }
  }, el.renderTo = function(e19, t14, n11, r8) {
    this.render({ forcedContext: e19, forcedZoom: t14, forcedPan: n11, drawAllLayers: true, forcedPxRatio: r8 });
  }, el.render = function(e19) {
    var t14 = (e19 = e19 || Ie()).forcedContext, n11 = e19.drawAllLayers, r8 = e19.drawOnlyNodeLayer, a8 = e19.forcedZoom, i9 = e19.forcedPan, o11 = this, s10 = void 0 === e19.forcedPxRatio ? this.getPixelRatio() : e19.forcedPxRatio, l10 = o11.cy, u9 = o11.data, c9 = u9.canvasNeedsRedraw, d10 = o11.textureOnViewport && !t14 && (o11.pinching || o11.hoverData.dragging || o11.swipePanning || o11.data.wheelZooming), h9 = void 0 !== e19.motionBlur ? e19.motionBlur : o11.motionBlur, p9 = o11.motionBlurPxRatio, f10 = l10.hasCompoundNodes(), g8 = o11.hoverData.draggingEles, v11 = !(!o11.hoverData.selecting && !o11.touchData.selecting), y9 = h9 = h9 && !t14 && o11.motionBlurEnabled && !v11;
    t14 || (o11.prevPxRatio !== s10 && (o11.invalidateContainerClientCoordsCache(), o11.matchCanvasSize(o11.container), o11.redrawHint("eles", true), o11.redrawHint("drag", true)), o11.prevPxRatio = s10), !t14 && o11.motionBlurTimeout && clearTimeout(o11.motionBlurTimeout), h9 && (null == o11.mbFrames && (o11.mbFrames = 0), o11.mbFrames++, o11.mbFrames < 3 && (y9 = false), o11.mbFrames > o11.minMbLowQualFrames && (o11.motionBlurPxRatio = o11.mbPxRBlurry)), o11.clearingMotionBlur && (o11.motionBlurPxRatio = 1), o11.textureDrawLastFrame && !d10 && (c9[o11.NODE] = true, c9[o11.SELECT_BOX] = true);
    var m11 = l10.style(), b10 = l10.zoom(), x10 = void 0 !== a8 ? a8 : b10, w9 = l10.pan(), E8 = { x: w9.x, y: w9.y }, k9 = { zoom: b10, pan: { x: w9.x, y: w9.y } }, C8 = o11.prevViewport;
    void 0 === C8 || k9.zoom !== C8.zoom || k9.pan.x !== C8.pan.x || k9.pan.y !== C8.pan.y || g8 && !f10 || (o11.motionBlurPxRatio = 1), i9 && (E8 = i9), x10 *= s10, E8.x *= s10, E8.y *= s10;
    var S7 = o11.getCachedZSortedEles();
    function D7(e20, t15, n12, r9, a9) {
      var i10 = e20.globalCompositeOperation;
      e20.globalCompositeOperation = "destination-out", o11.colorFillStyle(e20, 255, 255, 255, o11.motionBlurTransparency), e20.fillRect(t15, n12, r9, a9), e20.globalCompositeOperation = i10;
    }
    function P9(e20, r9) {
      var s11, l11, c10, d11;
      o11.clearingMotionBlur || e20 !== u9.bufferContexts[o11.MOTIONBLUR_BUFFER_NODE] && e20 !== u9.bufferContexts[o11.MOTIONBLUR_BUFFER_DRAG] ? (s11 = E8, l11 = x10, c10 = o11.canvasWidth, d11 = o11.canvasHeight) : (s11 = { x: w9.x * p9, y: w9.y * p9 }, l11 = b10 * p9, c10 = o11.canvasWidth * p9, d11 = o11.canvasHeight * p9), e20.setTransform(1, 0, 0, 1, 0, 0), "motionBlur" === r9 ? D7(e20, 0, 0, c10, d11) : t14 || void 0 !== r9 && !r9 || e20.clearRect(0, 0, c10, d11), n11 || (e20.translate(s11.x, s11.y), e20.scale(l11, l11)), i9 && e20.translate(i9.x, i9.y), a8 && e20.scale(a8, a8);
    }
    if (d10 || (o11.textureDrawLastFrame = false), d10) {
      if (o11.textureDrawLastFrame = true, !o11.textureCache) {
        o11.textureCache = {}, o11.textureCache.bb = l10.mutableElements().boundingBox(), o11.textureCache.texture = o11.data.bufferCanvases[o11.TEXTURE_BUFFER];
        var T8 = o11.data.bufferContexts[o11.TEXTURE_BUFFER];
        T8.setTransform(1, 0, 0, 1, 0, 0), T8.clearRect(0, 0, o11.canvasWidth * o11.textureMult, o11.canvasHeight * o11.textureMult), o11.render({ forcedContext: T8, drawOnlyNodeLayer: true, forcedPxRatio: s10 * o11.textureMult }), (k9 = o11.textureCache.viewport = { zoom: l10.zoom(), pan: l10.pan(), width: o11.canvasWidth, height: o11.canvasHeight }).mpan = { x: (0 - k9.pan.x) / k9.zoom, y: (0 - k9.pan.y) / k9.zoom };
      }
      c9[o11.DRAG] = false, c9[o11.NODE] = false;
      var M8 = u9.contexts[o11.NODE], B8 = o11.textureCache.texture;
      k9 = o11.textureCache.viewport;
      M8.setTransform(1, 0, 0, 1, 0, 0), h9 ? D7(M8, 0, 0, k9.width, k9.height) : M8.clearRect(0, 0, k9.width, k9.height);
      var _6 = m11.core("outside-texture-bg-color").value, N7 = m11.core("outside-texture-bg-opacity").value;
      o11.colorFillStyle(M8, _6[0], _6[1], _6[2], N7), M8.fillRect(0, 0, k9.width, k9.height);
      b10 = l10.zoom();
      P9(M8, false), M8.clearRect(k9.mpan.x, k9.mpan.y, k9.width / k9.zoom / s10, k9.height / k9.zoom / s10), M8.drawImage(B8, k9.mpan.x, k9.mpan.y, k9.width / k9.zoom / s10, k9.height / k9.zoom / s10);
    } else
      o11.textureOnViewport && !t14 && (o11.textureCache = null);
    var I7 = l10.extent(), z7 = o11.pinching || o11.hoverData.dragging || o11.swipePanning || o11.data.wheelZooming || o11.hoverData.draggingEles || o11.cy.animated(), L9 = o11.hideEdgesOnViewport && z7, A9 = [];
    if (A9[o11.NODE] = !c9[o11.NODE] && h9 && !o11.clearedForMotionBlur[o11.NODE] || o11.clearingMotionBlur, A9[o11.NODE] && (o11.clearedForMotionBlur[o11.NODE] = true), A9[o11.DRAG] = !c9[o11.DRAG] && h9 && !o11.clearedForMotionBlur[o11.DRAG] || o11.clearingMotionBlur, A9[o11.DRAG] && (o11.clearedForMotionBlur[o11.DRAG] = true), c9[o11.NODE] || n11 || r8 || A9[o11.NODE]) {
      var O8 = h9 && !A9[o11.NODE] && 1 !== p9;
      P9(M8 = t14 || (O8 ? o11.data.bufferContexts[o11.MOTIONBLUR_BUFFER_NODE] : u9.contexts[o11.NODE]), h9 && !O8 ? "motionBlur" : void 0), L9 ? o11.drawCachedNodes(M8, S7.nondrag, s10, I7) : o11.drawLayeredElements(M8, S7.nondrag, s10, I7), o11.debug && o11.drawDebugPoints(M8, S7.nondrag), n11 || h9 || (c9[o11.NODE] = false);
    }
    if (!r8 && (c9[o11.DRAG] || n11 || A9[o11.DRAG])) {
      O8 = h9 && !A9[o11.DRAG] && 1 !== p9;
      P9(M8 = t14 || (O8 ? o11.data.bufferContexts[o11.MOTIONBLUR_BUFFER_DRAG] : u9.contexts[o11.DRAG]), h9 && !O8 ? "motionBlur" : void 0), L9 ? o11.drawCachedNodes(M8, S7.drag, s10, I7) : o11.drawCachedElements(M8, S7.drag, s10, I7), o11.debug && o11.drawDebugPoints(M8, S7.drag), n11 || h9 || (c9[o11.DRAG] = false);
    }
    if (o11.showFps || !r8 && c9[o11.SELECT_BOX] && !n11) {
      if (P9(M8 = t14 || u9.contexts[o11.SELECT_BOX]), 1 == o11.selection[4] && (o11.hoverData.selecting || o11.touchData.selecting)) {
        b10 = o11.cy.zoom();
        var R7 = m11.core("selection-box-border-width").value / b10;
        M8.lineWidth = R7, M8.fillStyle = "rgba(" + m11.core("selection-box-color").value[0] + "," + m11.core("selection-box-color").value[1] + "," + m11.core("selection-box-color").value[2] + "," + m11.core("selection-box-opacity").value + ")", M8.fillRect(o11.selection[0], o11.selection[1], o11.selection[2] - o11.selection[0], o11.selection[3] - o11.selection[1]), R7 > 0 && (M8.strokeStyle = "rgba(" + m11.core("selection-box-border-color").value[0] + "," + m11.core("selection-box-border-color").value[1] + "," + m11.core("selection-box-border-color").value[2] + "," + m11.core("selection-box-opacity").value + ")", M8.strokeRect(o11.selection[0], o11.selection[1], o11.selection[2] - o11.selection[0], o11.selection[3] - o11.selection[1]));
      }
      if (u9.bgActivePosistion && !o11.hoverData.selecting) {
        b10 = o11.cy.zoom();
        var V6 = u9.bgActivePosistion;
        M8.fillStyle = "rgba(" + m11.core("active-bg-color").value[0] + "," + m11.core("active-bg-color").value[1] + "," + m11.core("active-bg-color").value[2] + "," + m11.core("active-bg-opacity").value + ")", M8.beginPath(), M8.arc(V6.x, V6.y, m11.core("active-bg-size").pfValue / b10, 0, 2 * Math.PI), M8.fill();
      }
      var F7 = o11.lastRedrawTime;
      if (o11.showFps && F7) {
        F7 = Math.round(F7);
        var q7 = Math.round(1e3 / F7);
        M8.setTransform(1, 0, 0, 1, 0, 0), M8.fillStyle = "rgba(255, 0, 0, 0.75)", M8.strokeStyle = "rgba(255, 0, 0, 0.75)", M8.lineWidth = 1, M8.fillText("1 frame = " + F7 + " ms = " + q7 + " fps", 0, 20);
        M8.strokeRect(0, 30, 250, 20), M8.fillRect(0, 30, 250 * Math.min(q7 / 60, 1), 20);
      }
      n11 || (c9[o11.SELECT_BOX] = false);
    }
    if (h9 && 1 !== p9) {
      var j8 = u9.contexts[o11.NODE], Y5 = o11.data.bufferCanvases[o11.MOTIONBLUR_BUFFER_NODE], X5 = u9.contexts[o11.DRAG], W7 = o11.data.bufferCanvases[o11.MOTIONBLUR_BUFFER_DRAG], H8 = function(e20, t15, n12) {
        e20.setTransform(1, 0, 0, 1, 0, 0), n12 || !y9 ? e20.clearRect(0, 0, o11.canvasWidth, o11.canvasHeight) : D7(e20, 0, 0, o11.canvasWidth, o11.canvasHeight);
        var r9 = p9;
        e20.drawImage(t15, 0, 0, o11.canvasWidth * r9, o11.canvasHeight * r9, 0, 0, o11.canvasWidth, o11.canvasHeight);
      };
      (c9[o11.NODE] || A9[o11.NODE]) && (H8(j8, Y5, A9[o11.NODE]), c9[o11.NODE] = false), (c9[o11.DRAG] || A9[o11.DRAG]) && (H8(X5, W7, A9[o11.DRAG]), c9[o11.DRAG] = false);
    }
    o11.prevViewport = k9, o11.clearingMotionBlur && (o11.clearingMotionBlur = false, o11.motionBlurCleared = true, o11.motionBlur = true), h9 && (o11.motionBlurTimeout = setTimeout(function() {
      o11.motionBlurTimeout = null, o11.clearedForMotionBlur[o11.NODE] = false, o11.clearedForMotionBlur[o11.DRAG] = false, o11.motionBlur = false, o11.clearingMotionBlur = !d10, o11.mbFrames = 0, c9[o11.NODE] = true, c9[o11.DRAG] = true, o11.redraw();
    }, 100)), t14 || l10.emit("render");
  };
  for (tl = { drawPolygonPath: function(e19, t14, n11, r8, a8, i9) {
    var o11 = r8 / 2, s10 = a8 / 2;
    e19.beginPath && e19.beginPath(), e19.moveTo(t14 + o11 * i9[0], n11 + s10 * i9[1]);
    for (var l10 = 1; l10 < i9.length / 2; l10++)
      e19.lineTo(t14 + o11 * i9[2 * l10], n11 + s10 * i9[2 * l10 + 1]);
    e19.closePath();
  }, drawRoundPolygonPath: function(e19, t14, n11, r8, a8, i9) {
    var o11 = r8 / 2, s10 = a8 / 2, l10 = Yt4(r8, a8);
    e19.beginPath && e19.beginPath();
    for (var u9 = 0; u9 < i9.length / 4; u9++) {
      var c9, d10 = void 0;
      d10 = 0 === u9 ? i9.length - 2 : 4 * u9 - 2, c9 = 4 * u9 + 2;
      var h9 = t14 + o11 * i9[4 * u9], p9 = n11 + s10 * i9[4 * u9 + 1], f10 = -i9[d10] * i9[c9] - i9[d10 + 1] * i9[c9 + 1], g8 = l10 / Math.tan(Math.acos(f10) / 2), v11 = h9 - g8 * i9[d10], y9 = p9 - g8 * i9[d10 + 1], m11 = h9 + g8 * i9[c9], b10 = p9 + g8 * i9[c9 + 1];
      0 === u9 ? e19.moveTo(v11, y9) : e19.lineTo(v11, y9), e19.arcTo(h9, p9, m11, b10, l10);
    }
    e19.closePath();
  }, drawRoundRectanglePath: function(e19, t14, n11, r8, a8) {
    var i9 = r8 / 2, o11 = a8 / 2, s10 = jt4(r8, a8);
    e19.beginPath && e19.beginPath(), e19.moveTo(t14, n11 - o11), e19.arcTo(t14 + i9, n11 - o11, t14 + i9, n11, s10), e19.arcTo(t14 + i9, n11 + o11, t14, n11 + o11, s10), e19.arcTo(t14 - i9, n11 + o11, t14 - i9, n11, s10), e19.arcTo(t14 - i9, n11 - o11, t14, n11 - o11, s10), e19.lineTo(t14, n11 - o11), e19.closePath();
  }, drawBottomRoundRectanglePath: function(e19, t14, n11, r8, a8) {
    var i9 = r8 / 2, o11 = a8 / 2, s10 = jt4(r8, a8);
    e19.beginPath && e19.beginPath(), e19.moveTo(t14, n11 - o11), e19.lineTo(t14 + i9, n11 - o11), e19.lineTo(t14 + i9, n11), e19.arcTo(t14 + i9, n11 + o11, t14, n11 + o11, s10), e19.arcTo(t14 - i9, n11 + o11, t14 - i9, n11, s10), e19.lineTo(t14 - i9, n11 - o11), e19.lineTo(t14, n11 - o11), e19.closePath();
  }, drawCutRectanglePath: function(e19, t14, n11, r8, a8) {
    var i9 = r8 / 2, o11 = a8 / 2;
    e19.beginPath && e19.beginPath(), e19.moveTo(t14 - i9 + 8, n11 - o11), e19.lineTo(t14 + i9 - 8, n11 - o11), e19.lineTo(t14 + i9, n11 - o11 + 8), e19.lineTo(t14 + i9, n11 + o11 - 8), e19.lineTo(t14 + i9 - 8, n11 + o11), e19.lineTo(t14 - i9 + 8, n11 + o11), e19.lineTo(t14 - i9, n11 + o11 - 8), e19.lineTo(t14 - i9, n11 - o11 + 8), e19.closePath();
  }, drawBarrelPath: function(e19, t14, n11, r8, a8) {
    var i9 = r8 / 2, o11 = a8 / 2, s10 = t14 - i9, l10 = t14 + i9, u9 = n11 - o11, c9 = n11 + o11, d10 = Xt4(r8, a8), h9 = d10.widthOffset, p9 = d10.heightOffset, f10 = d10.ctrlPtOffsetPct * h9;
    e19.beginPath && e19.beginPath(), e19.moveTo(s10, u9 + p9), e19.lineTo(s10, c9 - p9), e19.quadraticCurveTo(s10 + f10, c9, s10 + h9, c9), e19.lineTo(l10 - h9, c9), e19.quadraticCurveTo(l10 - f10, c9, l10, c9 - p9), e19.lineTo(l10, u9 + p9), e19.quadraticCurveTo(l10 - f10, u9, l10 - h9, u9), e19.lineTo(s10 + h9, u9), e19.quadraticCurveTo(s10 + f10, u9, s10, u9 + p9), e19.closePath();
  } }, nl = Math.sin(0), rl = Math.cos(0), al = {}, il = {}, ol = Math.PI / 40, sl = 0 * Math.PI; sl < 2 * Math.PI; sl += ol)
    al[sl] = Math.sin(sl), il[sl] = Math.cos(sl);
  var tl;
  var nl;
  var rl;
  var al;
  var il;
  var ol;
  var sl;
  tl.drawEllipsePath = function(e19, t14, n11, r8, a8) {
    if (e19.beginPath && e19.beginPath(), e19.ellipse)
      e19.ellipse(t14, n11, r8 / 2, a8 / 2, 0, 0, 2 * Math.PI);
    else
      for (var i9, o11, s10 = r8 / 2, l10 = a8 / 2, u9 = 0 * Math.PI; u9 < 2 * Math.PI; u9 += ol)
        i9 = t14 - s10 * al[u9] * nl + s10 * il[u9] * rl, o11 = n11 + l10 * il[u9] * nl + l10 * al[u9] * rl, 0 === u9 ? e19.moveTo(i9, o11) : e19.lineTo(i9, o11);
    e19.closePath();
  };
  var ll = {};
  function ul(e19) {
    var t14 = e19.indexOf(",");
    return e19.substr(t14 + 1);
  }
  function cl(e19, t14, n11) {
    var r8 = function() {
      return t14.toDataURL(n11, e19.quality);
    };
    switch (e19.output) {
      case "blob-promise":
        return new rr4(function(r9, a8) {
          try {
            t14.toBlob(function(e20) {
              null != e20 ? r9(e20) : a8(new Error("`canvas.toBlob()` sent a null value in its callback"));
            }, n11, e19.quality);
          } catch (e20) {
            a8(e20);
          }
        });
      case "blob":
        return function(e20, t15) {
          for (var n12 = atob(e20), r9 = new ArrayBuffer(n12.length), a8 = new Uint8Array(r9), i9 = 0; i9 < n12.length; i9++)
            a8[i9] = n12.charCodeAt(i9);
          return new Blob([r9], { type: t15 });
        }(ul(r8()), n11);
      case "base64":
        return ul(r8());
      default:
        return r8();
    }
  }
  ll.createBuffer = function(e19, t14) {
    var n11 = document.createElement("canvas");
    return n11.width = e19, n11.height = t14, [n11, n11.getContext("2d")];
  }, ll.bufferCanvasImage = function(e19) {
    var t14 = this.cy, n11 = t14.mutableElements().boundingBox(), r8 = this.findContainerClientCoords(), a8 = e19.full ? Math.ceil(n11.w) : r8[2], i9 = e19.full ? Math.ceil(n11.h) : r8[3], o11 = I6(e19.maxWidth) || I6(e19.maxHeight), s10 = this.getPixelRatio(), l10 = 1;
    if (void 0 !== e19.scale)
      a8 *= e19.scale, i9 *= e19.scale, l10 = e19.scale;
    else if (o11) {
      var u9 = 1 / 0, c9 = 1 / 0;
      I6(e19.maxWidth) && (u9 = l10 * e19.maxWidth / a8), I6(e19.maxHeight) && (c9 = l10 * e19.maxHeight / i9), a8 *= l10 = Math.min(u9, c9), i9 *= l10;
    }
    o11 || (a8 *= s10, i9 *= s10, l10 *= s10);
    var d10 = document.createElement("canvas");
    d10.width = a8, d10.height = i9, d10.style.width = a8 + "px", d10.style.height = i9 + "px";
    var h9 = d10.getContext("2d");
    if (a8 > 0 && i9 > 0) {
      h9.clearRect(0, 0, a8, i9), h9.globalCompositeOperation = "source-over";
      var p9 = this.getCachedZSortedEles();
      if (e19.full)
        h9.translate(-n11.x1 * l10, -n11.y1 * l10), h9.scale(l10, l10), this.drawElements(h9, p9), h9.scale(1 / l10, 1 / l10), h9.translate(n11.x1 * l10, n11.y1 * l10);
      else {
        var f10 = t14.pan(), g8 = { x: f10.x * l10, y: f10.y * l10 };
        l10 *= t14.zoom(), h9.translate(g8.x, g8.y), h9.scale(l10, l10), this.drawElements(h9, p9), h9.scale(1 / l10, 1 / l10), h9.translate(-g8.x, -g8.y);
      }
      e19.bg && (h9.globalCompositeOperation = "destination-over", h9.fillStyle = e19.bg, h9.rect(0, 0, a8, i9), h9.fill());
    }
    return d10;
  }, ll.png = function(e19) {
    return cl(e19, this.bufferCanvasImage(e19), "image/png");
  }, ll.jpg = function(e19) {
    return cl(e19, this.bufferCanvasImage(e19), "image/jpeg");
  };
  var dl = { nodeShapeImpl: function(e19, t14, n11, r8, a8, i9, o11) {
    switch (e19) {
      case "ellipse":
        return this.drawEllipsePath(t14, n11, r8, a8, i9);
      case "polygon":
        return this.drawPolygonPath(t14, n11, r8, a8, i9, o11);
      case "round-polygon":
        return this.drawRoundPolygonPath(t14, n11, r8, a8, i9, o11);
      case "roundrectangle":
      case "round-rectangle":
        return this.drawRoundRectanglePath(t14, n11, r8, a8, i9);
      case "cutrectangle":
      case "cut-rectangle":
        return this.drawCutRectanglePath(t14, n11, r8, a8, i9);
      case "bottomroundrectangle":
      case "bottom-round-rectangle":
        return this.drawBottomRoundRectanglePath(t14, n11, r8, a8, i9);
      case "barrel":
        return this.drawBarrelPath(t14, n11, r8, a8, i9);
    }
  } };
  var hl = fl;
  var pl = fl.prototype;
  function fl(e19) {
    var t14 = this;
    t14.data = { canvases: new Array(pl.CANVAS_LAYERS), contexts: new Array(pl.CANVAS_LAYERS), canvasNeedsRedraw: new Array(pl.CANVAS_LAYERS), bufferCanvases: new Array(pl.BUFFER_COUNT), bufferContexts: new Array(pl.CANVAS_LAYERS) };
    var n11 = "-webkit-tap-highlight-color", r8 = "rgba(0,0,0,0)";
    t14.data.canvasContainer = document.createElement("div");
    var a8 = t14.data.canvasContainer.style;
    t14.data.canvasContainer.style[n11] = r8, a8.position = "relative", a8.zIndex = "0", a8.overflow = "hidden";
    var i9 = e19.cy.container();
    i9.appendChild(t14.data.canvasContainer), i9.style[n11] = r8;
    var o11 = { "-webkit-user-select": "none", "-moz-user-select": "-moz-none", "user-select": "none", "-webkit-tap-highlight-color": "rgba(0,0,0,0)", "outline-style": "none" };
    k5 && k5.userAgent.match(/msie|trident|edge/i) && (o11["-ms-touch-action"] = "none", o11["touch-action"] = "none");
    for (var s10 = 0; s10 < pl.CANVAS_LAYERS; s10++) {
      var l10 = t14.data.canvases[s10] = document.createElement("canvas");
      t14.data.contexts[s10] = l10.getContext("2d"), Object.keys(o11).forEach(function(e20) {
        l10.style[e20] = o11[e20];
      }), l10.style.position = "absolute", l10.setAttribute("data-id", "layer" + s10), l10.style.zIndex = String(pl.CANVAS_LAYERS - s10), t14.data.canvasContainer.appendChild(l10), t14.data.canvasNeedsRedraw[s10] = false;
    }
    t14.data.topCanvas = t14.data.canvases[0], t14.data.canvases[pl.NODE].setAttribute("data-id", "layer" + pl.NODE + "-node"), t14.data.canvases[pl.SELECT_BOX].setAttribute("data-id", "layer" + pl.SELECT_BOX + "-selectbox"), t14.data.canvases[pl.DRAG].setAttribute("data-id", "layer" + pl.DRAG + "-drag");
    for (s10 = 0; s10 < pl.BUFFER_COUNT; s10++)
      t14.data.bufferCanvases[s10] = document.createElement("canvas"), t14.data.bufferContexts[s10] = t14.data.bufferCanvases[s10].getContext("2d"), t14.data.bufferCanvases[s10].style.position = "absolute", t14.data.bufferCanvases[s10].setAttribute("data-id", "buffer" + s10), t14.data.bufferCanvases[s10].style.zIndex = String(-s10 - 1), t14.data.bufferCanvases[s10].style.visibility = "hidden";
    t14.pathsEnabled = true;
    var u9 = vt4(), c9 = function(e20) {
      return { x: -e20.w / 2, y: -e20.h / 2 };
    }, d10 = function(e20) {
      return e20.boundingBox(), e20[0]._private.bodyBounds;
    }, h9 = function(e20) {
      return e20.boundingBox(), e20[0]._private.labelBounds.main || u9;
    }, p9 = function(e20) {
      return e20.boundingBox(), e20[0]._private.labelBounds.source || u9;
    }, f10 = function(e20) {
      return e20.boundingBox(), e20[0]._private.labelBounds.target || u9;
    }, g8 = function(e20, t15) {
      return t15;
    }, v11 = function(e20, t15, n12) {
      var r9 = e20 ? e20 + "-" : "";
      return { x: t15.x + n12.pstyle(r9 + "text-margin-x").pfValue, y: t15.y + n12.pstyle(r9 + "text-margin-y").pfValue };
    }, y9 = function(e20, t15, n12) {
      var r9 = e20[0]._private.rscratch;
      return { x: r9[t15], y: r9[n12] };
    }, m11 = t14.data.eleTxrCache = new Ts(t14, { getKey: function(e20) {
      return e20[0]._private.nodeKey;
    }, doesEleInvalidateKey: function(e20) {
      var t15 = e20[0]._private;
      return !(t15.oldBackgroundTimestamp === t15.backgroundTimestamp);
    }, drawElement: function(e20, n12, r9, a9, i10) {
      return t14.drawElement(e20, n12, r9, false, false, i10);
    }, getBoundingBox: d10, getRotationPoint: function(e20) {
      return { x: ((t15 = d10(e20)).x1 + t15.x2) / 2, y: (t15.y1 + t15.y2) / 2 };
      var t15;
    }, getRotationOffset: function(e20) {
      return c9(d10(e20));
    }, allowEdgeTxrCaching: false, allowParentTxrCaching: false }), b10 = t14.data.lblTxrCache = new Ts(t14, { getKey: function(e20) {
      return e20[0]._private.labelStyleKey;
    }, drawElement: function(e20, n12, r9, a9, i10) {
      return t14.drawElementText(e20, n12, r9, a9, "main", i10);
    }, getBoundingBox: h9, getRotationPoint: function(e20) {
      return v11("", y9(e20, "labelX", "labelY"), e20);
    }, getRotationOffset: function(e20) {
      var t15 = h9(e20), n12 = c9(h9(e20));
      if (e20.isNode()) {
        switch (e20.pstyle("text-halign").value) {
          case "left":
            n12.x = -t15.w;
            break;
          case "right":
            n12.x = 0;
        }
        switch (e20.pstyle("text-valign").value) {
          case "top":
            n12.y = -t15.h;
            break;
          case "bottom":
            n12.y = 0;
        }
      }
      return n12;
    }, isVisible: g8 }), x10 = t14.data.slbTxrCache = new Ts(t14, { getKey: function(e20) {
      return e20[0]._private.sourceLabelStyleKey;
    }, drawElement: function(e20, n12, r9, a9, i10) {
      return t14.drawElementText(e20, n12, r9, a9, "source", i10);
    }, getBoundingBox: p9, getRotationPoint: function(e20) {
      return v11("source", y9(e20, "sourceLabelX", "sourceLabelY"), e20);
    }, getRotationOffset: function(e20) {
      return c9(p9(e20));
    }, isVisible: g8 }), w9 = t14.data.tlbTxrCache = new Ts(t14, { getKey: function(e20) {
      return e20[0]._private.targetLabelStyleKey;
    }, drawElement: function(e20, n12, r9, a9, i10) {
      return t14.drawElementText(e20, n12, r9, a9, "target", i10);
    }, getBoundingBox: f10, getRotationPoint: function(e20) {
      return v11("target", y9(e20, "targetLabelX", "targetLabelY"), e20);
    }, getRotationOffset: function(e20) {
      return c9(f10(e20));
    }, isVisible: g8 }), E8 = t14.data.lyrTxrCache = new Bs(t14);
    t14.onUpdateEleCalcs(function(e20, t15) {
      m11.invalidateElements(t15), b10.invalidateElements(t15), x10.invalidateElements(t15), w9.invalidateElements(t15), E8.invalidateElements(t15);
      for (var n12 = 0; n12 < t15.length; n12++) {
        var r9 = t15[n12]._private;
        r9.oldBackgroundTimestamp = r9.backgroundTimestamp;
      }
    });
    var C8 = function(e20) {
      for (var t15 = 0; t15 < e20.length; t15++)
        E8.enqueueElementRefinement(e20[t15].ele);
    };
    m11.onDequeue(C8), b10.onDequeue(C8), x10.onDequeue(C8), w9.onDequeue(C8);
  }
  pl.CANVAS_LAYERS = 3, pl.SELECT_BOX = 0, pl.DRAG = 1, pl.NODE = 2, pl.BUFFER_COUNT = 3, pl.TEXTURE_BUFFER = 0, pl.MOTIONBLUR_BUFFER_NODE = 1, pl.MOTIONBLUR_BUFFER_DRAG = 2, pl.redrawHint = function(e19, t14) {
    var n11 = this;
    switch (e19) {
      case "eles":
        n11.data.canvasNeedsRedraw[pl.NODE] = t14;
        break;
      case "drag":
        n11.data.canvasNeedsRedraw[pl.DRAG] = t14;
        break;
      case "select":
        n11.data.canvasNeedsRedraw[pl.SELECT_BOX] = t14;
    }
  };
  var gl = "undefined" != typeof Path2D;
  pl.path2dEnabled = function(e19) {
    if (void 0 === e19)
      return this.pathsEnabled;
    this.pathsEnabled = !!e19;
  }, pl.usePaths = function() {
    return gl && this.pathsEnabled;
  }, pl.setImgSmoothing = function(e19, t14) {
    null != e19.imageSmoothingEnabled ? e19.imageSmoothingEnabled = t14 : (e19.webkitImageSmoothingEnabled = t14, e19.mozImageSmoothingEnabled = t14, e19.msImageSmoothingEnabled = t14);
  }, pl.getImgSmoothing = function(e19) {
    return null != e19.imageSmoothingEnabled ? e19.imageSmoothingEnabled : e19.webkitImageSmoothingEnabled || e19.mozImageSmoothingEnabled || e19.msImageSmoothingEnabled;
  }, pl.makeOffscreenCanvas = function(e19, t14) {
    var n11;
    return "undefined" !== ("undefined" == typeof OffscreenCanvas ? "undefined" : g6(OffscreenCanvas)) ? n11 = new OffscreenCanvas(e19, t14) : ((n11 = document.createElement("canvas")).width = e19, n11.height = t14), n11;
  }, [Ls, qs, Gs, Zs, $s, Qs, el, tl, ll, dl].forEach(function(e19) {
    J4(pl, e19);
  });
  var vl = [{ type: "layout", extensions: Zo }, { type: "renderer", extensions: [{ name: "null", impl: $o }, { name: "base", impl: ws }, { name: "canvas", impl: hl }] }];
  var yl = {};
  var ml = {};
  function bl(e19, t14, n11) {
    var r8 = n11, a8 = function(n12) {
      Me("Can not register `" + t14 + "` for `" + e19 + "` since `" + n12 + "` already exists in the prototype and can not be overridden");
    };
    if ("core" === e19) {
      if (lo.prototype[t14])
        return a8(t14);
      lo.prototype[t14] = n11;
    } else if ("collection" === e19) {
      if (Ci.prototype[t14])
        return a8(t14);
      Ci.prototype[t14] = n11;
    } else if ("layout" === e19) {
      for (var i9 = function(e20) {
        this.options = e20, n11.call(this, e20), N6(this._private) || (this._private = {}), this._private.cy = e20.cy, this._private.listeners = [], this.createEmitter();
      }, o11 = i9.prototype = Object.create(n11.prototype), s10 = [], l10 = 0; l10 < s10.length; l10++) {
        var u9 = s10[l10];
        o11[u9] = o11[u9] || function() {
          return this;
        };
      }
      o11.start && !o11.run ? o11.run = function() {
        return this.start(), this;
      } : !o11.start && o11.run && (o11.start = function() {
        return this.run(), this;
      });
      var c9 = n11.prototype.stop;
      o11.stop = function() {
        var e20 = this.options;
        if (e20 && e20.animate) {
          var t15 = this.animations;
          if (t15)
            for (var n12 = 0; n12 < t15.length; n12++)
              t15[n12].stop();
        }
        return c9 ? c9.call(this) : this.emit("layoutstop"), this;
      }, o11.destroy || (o11.destroy = function() {
        return this;
      }), o11.cy = function() {
        return this._private.cy;
      };
      var d10 = function(e20) {
        return e20._private.cy;
      }, h9 = { addEventFields: function(e20, t15) {
        t15.layout = e20, t15.cy = d10(e20), t15.target = e20;
      }, bubble: function() {
        return true;
      }, parent: function(e20) {
        return d10(e20);
      } };
      J4(o11, { createEmitter: function() {
        return this._private.emitter = new ja(h9, this), this;
      }, emitter: function() {
        return this._private.emitter;
      }, on: function(e20, t15) {
        return this.emitter().on(e20, t15), this;
      }, one: function(e20, t15) {
        return this.emitter().one(e20, t15), this;
      }, once: function(e20, t15) {
        return this.emitter().one(e20, t15), this;
      }, removeListener: function(e20, t15) {
        return this.emitter().removeListener(e20, t15), this;
      }, removeAllListeners: function() {
        return this.emitter().removeAllListeners(), this;
      }, emit: function(e20, t15) {
        return this.emitter().emit(e20, t15), this;
      } }), ur3.eventAliasesOn(o11), r8 = i9;
    } else if ("renderer" === e19 && "null" !== t14 && "base" !== t14) {
      var p9 = xl("renderer", "base"), f10 = p9.prototype, g8 = n11, v11 = n11.prototype, y9 = function() {
        p9.apply(this, arguments), g8.apply(this, arguments);
      }, m11 = y9.prototype;
      for (var b10 in f10) {
        var x10 = f10[b10];
        if (null != v11[b10])
          return a8(b10);
        m11[b10] = x10;
      }
      for (var w9 in v11)
        m11[w9] = v11[w9];
      f10.clientFunctions.forEach(function(e20) {
        m11[e20] = m11[e20] || function() {
          Pe("Renderer does not implement `renderer." + e20 + "()` on its prototype");
        };
      }), r8 = y9;
    } else if ("__proto__" === e19 || "constructor" === e19 || "prototype" === e19)
      return Pe(e19 + " is an illegal type to be registered, possibly lead to prototype pollutions");
    return ne({ map: yl, keys: [e19, t14], value: r8 });
  }
  function xl(e19, t14) {
    return re({ map: yl, keys: [e19, t14] });
  }
  function wl(e19, t14, n11, r8, a8) {
    return ne({ map: ml, keys: [e19, t14, n11, r8], value: a8 });
  }
  function El(e19, t14, n11, r8) {
    return re({ map: ml, keys: [e19, t14, n11, r8] });
  }
  var kl = function() {
    return 2 === arguments.length ? xl.apply(null, arguments) : 3 === arguments.length ? bl.apply(null, arguments) : 4 === arguments.length ? El.apply(null, arguments) : 5 === arguments.length ? wl.apply(null, arguments) : void Pe("Invalid extension access syntax");
  };
  lo.prototype.extension = kl, vl.forEach(function(e19) {
    e19.extensions.forEach(function(t14) {
      bl(e19.type, t14.name, t14.impl);
    });
  });
  var Cl = function e15() {
    if (!(this instanceof e15))
      return new e15();
    this.length = 0;
  };
  var Sl = Cl.prototype;
  Sl.instanceString = function() {
    return "stylesheet";
  }, Sl.selector = function(e19) {
    return this[this.length++] = { selector: e19, properties: [] }, this;
  }, Sl.css = function(e19, t14) {
    var n11 = this.length - 1;
    if (M6(e19))
      this[n11].properties.push({ name: e19, value: t14 });
    else if (N6(e19))
      for (var r8 = e19, a8 = Object.keys(r8), i9 = 0; i9 < a8.length; i9++) {
        var o11 = a8[i9], s10 = r8[o11];
        if (null != s10) {
          var l10 = ro.properties[o11] || ro.properties[X4(o11)];
          if (null != l10) {
            var u9 = l10.name, c9 = s10;
            this[n11].properties.push({ name: u9, value: c9 });
          }
        }
      }
    return this;
  }, Sl.style = Sl.css, Sl.generateStyle = function(e19) {
    var t14 = new ro(e19);
    return this.appendToStyle(t14);
  }, Sl.appendToStyle = function(e19) {
    for (var t14 = 0; t14 < this.length; t14++) {
      var n11 = this[t14], r8 = n11.selector, a8 = n11.properties;
      e19.selector(r8);
      for (var i9 = 0; i9 < a8.length; i9++) {
        var o11 = a8[i9];
        e19.css(o11.name, o11.value);
      }
    }
    return e19;
  };
  var Dl = function(e19) {
    return void 0 === e19 && (e19 = {}), N6(e19) ? new lo(e19) : M6(e19) ? kl.apply(kl, arguments) : void 0;
  };
  Dl.use = function(e19) {
    var t14 = Array.prototype.slice.call(arguments, 1);
    return t14.unshift(Dl), e19.apply(null, t14), this;
  }, Dl.warnings = function(e19) {
    return Te(e19);
  }, Dl.version = "3.26.0", Dl.stylesheet = Dl.Stylesheet = Cl;
  var Pl = Dl;
  var Tl = Pl.stylesheet;
  var Ml = Pl.use;
  var Bl = Pl.version;
  var _l = Pl.warnings;

  // http-url:https://cdn.jsdelivr.net/npm/@floating-ui/utils@0.1.6/+esm
  var t11 = ["top", "right", "bottom", "left"];
  var n8 = ["start", "end"];
  var o8 = t11.reduce((t14, o11) => t14.concat(o11, o11 + "-" + n8[0], o11 + "-" + n8[1]), []);
  var r6 = Math.min;
  var e16 = Math.max;
  var u7 = Math.round;
  var c7 = (t14) => ({ x: t14, y: t14 });
  var f7 = { left: "right", right: "left", bottom: "top", top: "bottom" };
  var a6 = { start: "end", end: "start" };
  function h7(t14, n11) {
    return "function" == typeof t14 ? t14(n11) : t14;
  }
  function p7(t14) {
    return t14.split("-")[0];
  }
  function s7(t14) {
    return t14.split("-")[1];
  }
  function m8(t14) {
    return "x" === t14 ? "y" : "x";
  }
  function g7(t14) {
    return "y" === t14 ? "height" : "width";
  }
  function b7(t14) {
    return ["top", "bottom"].includes(p7(t14)) ? "y" : "x";
  }
  function d7(t14) {
    return m8(b7(t14));
  }
  function x7(t14, n11, o11) {
    void 0 === o11 && (o11 = false);
    const r8 = s7(t14), e19 = d7(t14), u9 = g7(e19);
    let i9 = "x" === e19 ? r8 === (o11 ? "end" : "start") ? "right" : "left" : "start" === r8 ? "bottom" : "top";
    return n11.reference[u9] > n11.floating[u9] && (i9 = v7(i9)), [i9, v7(i9)];
  }
  function y7(t14) {
    const n11 = v7(t14);
    return [M7(t14), n11, M7(n11)];
  }
  function M7(t14) {
    return t14.replace(/start|end/g, (t15) => a6[t15]);
  }
  function w7(t14, n11, o11, r8) {
    const e19 = s7(t14);
    let u9 = function(t15, n12, o12) {
      const r9 = ["left", "right"], e20 = ["right", "left"], u10 = ["top", "bottom"], i9 = ["bottom", "top"];
      switch (t15) {
        case "top":
        case "bottom":
          return o12 ? n12 ? e20 : r9 : n12 ? r9 : e20;
        case "left":
        case "right":
          return n12 ? u10 : i9;
        default:
          return [];
      }
    }(p7(t14), "start" === o11, r8);
    return e19 && (u9 = u9.map((t15) => t15 + "-" + e19), n11 && (u9 = u9.concat(u9.map(M7)))), u9;
  }
  function v7(t14) {
    return t14.replace(/left|right|bottom|top/g, (t15) => f7[t15]);
  }
  function j7(t14) {
    return { top: 0, right: 0, bottom: 0, left: 0, ...t14 };
  }
  function k6(t14) {
    return "number" != typeof t14 ? j7(t14) : { top: t14, right: t14, bottom: t14, left: t14 };
  }
  function q6(t14) {
    return { ...t14, top: t14.y, left: t14.x, right: t14.x + t14.width, bottom: t14.y + t14.height };
  }

  // http-url:https://cdn.jsdelivr.net/npm/@floating-ui/core@1.5.0/+esm
  function x8(e19, t14, n11) {
    let { reference: r8, floating: a8 } = e19;
    const s10 = b7(t14), c9 = d7(t14), m11 = g7(c9), u9 = p7(t14), g8 = "y" === s10, p9 = r8.x + r8.width / 2 - a8.width / 2, h9 = r8.y + r8.height / 2 - a8.height / 2, y9 = r8[m11] / 2 - a8[m11] / 2;
    let w9;
    switch (u9) {
      case "top":
        w9 = { x: p9, y: r8.y - a8.height };
        break;
      case "bottom":
        w9 = { x: p9, y: r8.y + r8.height };
        break;
      case "right":
        w9 = { x: r8.x + r8.width, y: h9 };
        break;
      case "left":
        w9 = { x: r8.x - a8.width, y: h9 };
        break;
      default:
        w9 = { x: r8.x, y: r8.y };
    }
    switch (s7(t14)) {
      case "start":
        w9[c9] -= y9 * (n11 && g8 ? -1 : 1);
        break;
      case "end":
        w9[c9] += y9 * (n11 && g8 ? -1 : 1);
    }
    return w9;
  }
  var v8 = async (e19, t14, n11) => {
    const { placement: i9 = "bottom", strategy: o11 = "absolute", middleware: r8 = [], platform: a8 } = n11, l10 = r8.filter(Boolean), s10 = await (null == a8.isRTL ? void 0 : a8.isRTL(t14));
    let c9 = await a8.getElementRects({ reference: e19, floating: t14, strategy: o11 }), { x: f10, y: m11 } = x8(c9, i9, s10), u9 = i9, g8 = {}, d10 = 0;
    for (let n12 = 0; n12 < l10.length; n12++) {
      const { name: r9, fn: p9 } = l10[n12], { x: h9, y: y9, data: w9, reset: v11 } = await p9({ x: f10, y: m11, initialPlacement: i9, placement: u9, strategy: o11, middlewareData: g8, rects: c9, platform: a8, elements: { reference: e19, floating: t14 } });
      f10 = null != h9 ? h9 : f10, m11 = null != y9 ? y9 : m11, g8 = { ...g8, [r9]: { ...g8[r9], ...w9 } }, v11 && d10 <= 50 && (d10++, "object" == typeof v11 && (v11.placement && (u9 = v11.placement), v11.rects && (c9 = true === v11.rects ? await a8.getElementRects({ reference: e19, floating: t14, strategy: o11 }) : v11.rects), { x: f10, y: m11 } = x8(c9, u9, s10)), n12 = -1);
    }
    return { x: f10, y: m11, placement: u9, strategy: o11, middlewareData: g8 };
  };
  async function b8(i9, o11) {
    var r8;
    void 0 === o11 && (o11 = {});
    const { x: a8, y: l10, platform: s10, rects: c9, elements: f10, strategy: m11 } = i9, { boundary: u9 = "clippingAncestors", rootBoundary: g8 = "viewport", elementContext: d10 = "floating", altBoundary: p9 = false, padding: h9 = 0 } = h7(o11, i9), y9 = k6(h9), w9 = f10[p9 ? "floating" === d10 ? "reference" : "floating" : d10], x10 = q6(await s10.getClippingRect({ element: null == (r8 = await (null == s10.isElement ? void 0 : s10.isElement(w9))) || r8 ? w9 : w9.contextElement || await (null == s10.getDocumentElement ? void 0 : s10.getDocumentElement(f10.floating)), boundary: u9, rootBoundary: g8, strategy: m11 })), v11 = "floating" === d10 ? { ...c9.floating, x: a8, y: l10 } : c9.reference, b10 = await (null == s10.getOffsetParent ? void 0 : s10.getOffsetParent(f10.floating)), A9 = await (null == s10.isElement ? void 0 : s10.isElement(b10)) && await (null == s10.getScale ? void 0 : s10.getScale(b10)) || { x: 1, y: 1 }, R7 = q6(s10.convertOffsetParentRelativeRectToViewportRelativeRect ? await s10.convertOffsetParentRelativeRectToViewportRelativeRect({ rect: v11, offsetParent: b10, strategy: m11 }) : v11);
    return { top: (x10.top - R7.top + y9.top) / A9.y, bottom: (R7.bottom - x10.bottom + y9.bottom) / A9.y, left: (x10.left - R7.left + y9.left) / A9.x, right: (R7.right - x10.right + y9.right) / A9.x };
  }
  var P7 = function(t14) {
    return void 0 === t14 && (t14 = {}), { name: "flip", options: t14, async fn(n11) {
      var i9, o11;
      const { placement: r8, middlewareData: a8, rects: l10, initialPlacement: s10, platform: d10, elements: p9 } = n11, { mainAxis: h9 = true, crossAxis: y9 = true, fallbackPlacements: w9, fallbackStrategy: x10 = "bestFit", fallbackAxisSideDirection: v11 = "none", flipAlignment: A9 = true, ...R7 } = h7(t14, n11);
      if (null != (i9 = a8.arrow) && i9.alignmentOffset)
        return {};
      const P9 = p7(r8), T8 = p7(s10) === s10, D7 = await (null == d10.isRTL ? void 0 : d10.isRTL(p9.floating)), E8 = w9 || (T8 || !A9 ? [v7(s10)] : y7(s10));
      w9 || "none" === v11 || E8.push(...w7(s10, A9, v11, D7));
      const O8 = [s10, ...E8], L9 = await b8(n11, R7), k9 = [];
      let C8 = (null == (o11 = a8.flip) ? void 0 : o11.overflows) || [];
      if (h9 && k9.push(L9[P9]), y9) {
        const e19 = x7(r8, l10, D7);
        k9.push(L9[e19[0]], L9[e19[1]]);
      }
      if (C8 = [...C8, { placement: r8, overflows: k9 }], !k9.every((e19) => e19 <= 0)) {
        var B8, H8;
        const e19 = ((null == (B8 = a8.flip) ? void 0 : B8.index) || 0) + 1, t15 = O8[e19];
        if (t15)
          return { data: { index: e19, overflows: C8 }, reset: { placement: t15 } };
        let n12 = null == (H8 = C8.filter((e20) => e20.overflows[0] <= 0).sort((e20, t16) => e20.overflows[1] - t16.overflows[1])[0]) ? void 0 : H8.placement;
        if (!n12)
          switch (x10) {
            case "bestFit": {
              var S7;
              const e20 = null == (S7 = C8.map((e21) => [e21.placement, e21.overflows.filter((e22) => e22 > 0).reduce((e22, t16) => e22 + t16, 0)]).sort((e21, t16) => e21[1] - t16[1])[0]) ? void 0 : S7[0];
              e20 && (n12 = e20);
              break;
            }
            case "initialPlacement":
              n12 = s10;
          }
        if (r8 !== n12)
          return { reset: { placement: n12 } };
      }
      return {};
    } };
  };

  // http-url:https://cdn.jsdelivr.net/npm/@floating-ui/utils@0.1.6/dom/+esm
  function n9(n11) {
    return o9(n11) ? (n11.nodeName || "").toLowerCase() : "#document";
  }
  function e17(n11) {
    var e19;
    return (null == n11 || null == (e19 = n11.ownerDocument) ? void 0 : e19.defaultView) || window;
  }
  function t12(n11) {
    var e19;
    return null == (e19 = (o9(n11) ? n11.ownerDocument : n11.document) || window.document) ? void 0 : e19.documentElement;
  }
  function o9(n11) {
    return n11 instanceof Node || n11 instanceof e17(n11).Node;
  }
  function r7(n11) {
    return n11 instanceof Element || n11 instanceof e17(n11).Element;
  }
  function c8(n11) {
    return n11 instanceof HTMLElement || n11 instanceof e17(n11).HTMLElement;
  }
  function u8(n11) {
    return "undefined" != typeof ShadowRoot && (n11 instanceof ShadowRoot || n11 instanceof e17(n11).ShadowRoot);
  }
  function i7(n11) {
    const { overflow: e19, overflowX: t14, overflowY: o11, display: r8 } = m9(n11);
    return /auto|scroll|overlay|hidden|clip/.test(e19 + o11 + t14) && !["inline", "contents"].includes(r8);
  }
  function l8(e19) {
    return ["table", "td", "th"].includes(n9(e19));
  }
  function f8(n11) {
    const e19 = a7(), t14 = m9(n11);
    return "none" !== t14.transform || "none" !== t14.perspective || !!t14.containerType && "normal" !== t14.containerType || !e19 && !!t14.backdropFilter && "none" !== t14.backdropFilter || !e19 && !!t14.filter && "none" !== t14.filter || ["transform", "perspective", "filter"].some((n12) => (t14.willChange || "").includes(n12)) || ["paint", "layout", "strict", "content"].some((n12) => (t14.contain || "").includes(n12));
  }
  function s8(n11) {
    let e19 = w8(n11);
    for (; c8(e19) && !d8(e19); ) {
      if (f8(e19))
        return e19;
      e19 = w8(e19);
    }
    return null;
  }
  function a7() {
    return !("undefined" == typeof CSS || !CSS.supports) && CSS.supports("-webkit-backdrop-filter", "none");
  }
  function d8(e19) {
    return ["html", "body", "#document"].includes(n9(e19));
  }
  function m9(n11) {
    return e17(n11).getComputedStyle(n11);
  }
  function p8(n11) {
    return r7(n11) ? { scrollLeft: n11.scrollLeft, scrollTop: n11.scrollTop } : { scrollLeft: n11.pageXOffset, scrollTop: n11.pageYOffset };
  }
  function w8(e19) {
    if ("html" === n9(e19))
      return e19;
    const o11 = e19.assignedSlot || e19.parentNode || u8(e19) && e19.host || t12(e19);
    return u8(o11) ? o11.host : o11;
  }
  function v9(n11) {
    const e19 = w8(n11);
    return d8(e19) ? n11.ownerDocument ? n11.ownerDocument.body : n11.body : c8(e19) && i7(e19) ? e19 : v9(e19);
  }
  function y8(n11, t14, o11) {
    var r8;
    void 0 === t14 && (t14 = []), void 0 === o11 && (o11 = true);
    const c9 = v9(n11), u9 = c9 === (null == (r8 = n11.ownerDocument) ? void 0 : r8.body), l10 = e17(c9);
    return u9 ? t14.concat(l10, l10.visualViewport || [], i7(c9) ? c9 : [], l10.frameElement && o11 ? y8(l10.frameElement) : []) : t14.concat(c9, y8(c9, [], o11));
  }

  // http-url:https://cdn.jsdelivr.net/npm/@floating-ui/dom@1.5.1/+esm
  function L7(t14) {
    const e19 = m9(t14);
    let n11 = parseFloat(e19.width) || 0, o11 = parseFloat(e19.height) || 0;
    const r8 = c8(t14), l10 = r8 ? t14.offsetWidth : n11, c9 = r8 ? t14.offsetHeight : o11, s10 = u7(n11) !== l10 || u7(o11) !== c9;
    return s10 && (n11 = l10, o11 = c9), { width: n11, height: o11, $: s10 };
  }
  function R6(t14) {
    return r7(t14) ? t14 : t14.contextElement;
  }
  function T7(t14) {
    const e19 = R6(t14);
    if (!c8(e19))
      return c7(1);
    const o11 = e19.getBoundingClientRect(), { width: r8, height: l10, $: c9 } = L7(e19);
    let s10 = (c9 ? u7(o11.width) : o11.width) / r8, f10 = (c9 ? u7(o11.height) : o11.height) / l10;
    return s10 && Number.isFinite(s10) || (s10 = 1), f10 && Number.isFinite(f10) || (f10 = 1), { x: s10, y: f10 };
  }
  var E7 = c7(0);
  function F6(t14) {
    const e19 = e17(t14);
    return a7() && e19.visualViewport ? { x: e19.visualViewport.offsetLeft, y: e19.visualViewport.offsetTop } : E7;
  }
  function O7(t14, i9, o11, r8) {
    void 0 === i9 && (i9 = false), void 0 === o11 && (o11 = false);
    const l10 = t14.getBoundingClientRect(), c9 = R6(t14);
    let f10 = c7(1);
    i9 && (r8 ? r7(r8) && (f10 = T7(r8)) : f10 = T7(t14));
    const u9 = function(t15, e19, n11) {
      return void 0 === e19 && (e19 = false), !(!n11 || e19 && n11 !== e17(t15)) && e19;
    }(c9, o11, r8) ? F6(c9) : c7(0);
    let d10 = (l10.left + u9.x) / f10.x, p9 = (l10.top + u9.y) / f10.y, g8 = l10.width / f10.x, m11 = l10.height / f10.y;
    if (c9) {
      const t15 = e17(c9), e19 = r8 && r7(r8) ? e17(r8) : r8;
      let n11 = t15.frameElement;
      for (; n11 && r8 && e19 !== t15; ) {
        const t16 = T7(n11), e20 = n11.getBoundingClientRect(), i10 = m9(n11), o12 = e20.left + (n11.clientLeft + parseFloat(i10.paddingLeft)) * t16.x, r9 = e20.top + (n11.clientTop + parseFloat(i10.paddingTop)) * t16.y;
        d10 *= t16.x, p9 *= t16.y, g8 *= t16.x, m11 *= t16.y, d10 += o12, p9 += r9, n11 = e17(n11).frameElement;
      }
    }
    return q6({ width: g8, height: m11, x: d10, y: p9 });
  }
  function W6(t14) {
    return O7(t12(t14)).left + p8(t14).scrollLeft;
  }
  function H7(t14, i9, r8) {
    let l10;
    if ("viewport" === i9)
      l10 = function(t15, e19) {
        const n11 = e17(t15), i10 = t12(t15), o11 = n11.visualViewport;
        let r9 = i10.clientWidth, l11 = i10.clientHeight, s10 = 0, f10 = 0;
        if (o11) {
          r9 = o11.width, l11 = o11.height;
          const t16 = a7();
          (!t16 || t16 && "fixed" === e19) && (s10 = o11.offsetLeft, f10 = o11.offsetTop);
        }
        return { width: r9, height: l11, x: s10, y: f10 };
      }(t14, r8);
    else if ("document" === i9)
      l10 = function(t15) {
        const e19 = t12(t15), n11 = p8(t15), i10 = t15.ownerDocument.body, r9 = e16(e19.scrollWidth, e19.clientWidth, i10.scrollWidth, i10.clientWidth), l11 = e16(e19.scrollHeight, e19.clientHeight, i10.scrollHeight, i10.clientHeight);
        let s10 = -n11.scrollLeft + W6(t15);
        const f10 = -n11.scrollTop;
        return "rtl" === m9(i10).direction && (s10 += e16(e19.clientWidth, i10.clientWidth) - r9), { width: r9, height: l11, x: s10, y: f10 };
      }(t12(t14));
    else if (r7(i9))
      l10 = function(t15, e19) {
        const i10 = O7(t15, true, "fixed" === e19), o11 = i10.top + t15.clientTop, r9 = i10.left + t15.clientLeft, l11 = c8(t15) ? T7(t15) : c7(1);
        return { width: t15.clientWidth * l11.x, height: t15.clientHeight * l11.y, x: r9 * l11.x, y: o11 * l11.y };
      }(i9, r8);
    else {
      const e19 = F6(t14);
      l10 = { ...i9, x: i9.x - e19.x, y: i9.y - e19.y };
    }
    return q6(l10);
  }
  function z6(t14, e19) {
    const n11 = w8(t14);
    return !(n11 === e19 || !r7(n11) || d8(n11)) && ("fixed" === m9(n11).position || z6(n11, e19));
  }
  function A8(t14, e19, i9) {
    const o11 = c8(e19), r8 = t12(e19), l10 = "fixed" === i9, s10 = O7(t14, true, l10, e19);
    let f10 = { scrollLeft: 0, scrollTop: 0 };
    const h9 = c7(0);
    if (o11 || !o11 && !l10)
      if (("body" !== n9(e19) || i7(r8)) && (f10 = p8(e19)), o11) {
        const t15 = O7(e19, true, l10, e19);
        h9.x = t15.x + e19.clientLeft, h9.y = t15.y + e19.clientTop;
      } else
        r8 && (h9.x = W6(r8));
    return { x: s10.left + f10.scrollLeft - h9.x, y: s10.top + f10.scrollTop - h9.y, width: s10.width, height: s10.height };
  }
  function C7(t14, e19) {
    return c8(t14) && "fixed" !== m9(t14).position ? e19 ? e19(t14) : t14.offsetParent : null;
  }
  function P8(t14, e19) {
    const n11 = e17(t14);
    if (!c8(t14))
      return n11;
    let i9 = C7(t14, e19);
    for (; i9 && l8(i9) && "static" === m9(i9).position; )
      i9 = C7(i9, e19);
    return i9 && ("html" === n9(i9) || "body" === n9(i9) && "static" === m9(i9).position && !f8(i9)) ? n11 : i9 || s8(t14) || n11;
  }
  var B7 = { convertOffsetParentRelativeRectToViewportRelativeRect: function(t14) {
    let { rect: e19, offsetParent: i9, strategy: o11 } = t14;
    const r8 = c8(i9), l10 = t12(i9);
    if (i9 === l10)
      return e19;
    let s10 = { scrollLeft: 0, scrollTop: 0 }, f10 = c7(1);
    const h9 = c7(0);
    if ((r8 || !r8 && "fixed" !== o11) && (("body" !== n9(i9) || i7(l10)) && (s10 = p8(i9)), c8(i9))) {
      const t15 = O7(i9);
      f10 = T7(i9), h9.x = t15.x + i9.clientLeft, h9.y = t15.y + i9.clientTop;
    }
    return { width: e19.width * f10.x, height: e19.height * f10.y, x: e19.x * f10.x - s10.scrollLeft * f10.x + h9.x, y: e19.y * f10.y - s10.scrollTop * f10.y + h9.y };
  }, getDocumentElement: t12, getClippingRect: function(t14) {
    let { element: e19, boundary: n11, rootBoundary: i9, strategy: l10 } = t14;
    const c9 = [..."clippingAncestors" === n11 ? function(t15, e20) {
      const n12 = e20.get(t15);
      if (n12)
        return n12;
      let i10 = y8(t15).filter((t16) => r7(t16) && "body" !== n9(t16)), o11 = null;
      const r8 = "fixed" === m9(t15).position;
      let l11 = r8 ? w8(t15) : t15;
      for (; r7(l11) && !d8(l11); ) {
        const e21 = m9(l11), n13 = f8(l11);
        n13 || "fixed" !== e21.position || (o11 = null), (r8 ? !n13 && !o11 : !n13 && "static" === e21.position && o11 && ["absolute", "fixed"].includes(o11.position) || i7(l11) && !n13 && z6(t15, l11)) ? i10 = i10.filter((t16) => t16 !== l11) : o11 = e21, l11 = w8(l11);
      }
      return e20.set(t15, i10), i10;
    }(e19, this._c) : [].concat(n11), i9], u9 = c9[0], h9 = c9.reduce((t15, n12) => {
      const i10 = H7(e19, n12, l10);
      return t15.top = e16(i10.top, t15.top), t15.right = r6(i10.right, t15.right), t15.bottom = r6(i10.bottom, t15.bottom), t15.left = e16(i10.left, t15.left), t15;
    }, H7(e19, u9, l10));
    return { width: h9.right - h9.left, height: h9.bottom - h9.top, x: h9.left, y: h9.top };
  }, getOffsetParent: P8, getElementRects: async function(t14) {
    let { reference: e19, floating: n11, strategy: i9 } = t14;
    const o11 = this.getOffsetParent || P8, r8 = this.getDimensions;
    return { reference: A8(e19, await o11(n11), i9), floating: { x: 0, y: 0, ...await r8(n11) } };
  }, getClientRects: function(t14) {
    return Array.from(t14.getClientRects());
  }, getDimensions: function(t14) {
    return L7(t14);
  }, getScale: T7, isElement: r7, isRTL: function(t14) {
    return "rtl" === m9(t14).direction;
  } };
  var V5 = (e19, n11, i9) => {
    const o11 = /* @__PURE__ */ new Map(), r8 = { platform: B7, ...i9 }, l10 = { ...r8.platform, _c: o11 };
    return v8(e19, n11, { ...r8, platform: l10 });
  };

  // tooltip.js
  var Tooltip = class extends m {
    constructor() {
      super();
      this.state = {
        style: {
          visibility: "hidden",
          left: 0,
          top: 0,
          zIndex: 0
        },
        mode: null
      };
    }
    attachTo(cyNode) {
      this.setState({ node: cyNode }, () => this.refreshPosition());
    }
    refreshPosition() {
      const { x: x10, y: y9 } = this.state.node.cy().container().getBoundingClientRect();
      const tooltip = this.base;
      const theNode = this.state.node;
      const virtualElt = {
        getBoundingClientRect() {
          const bbox = theNode.renderedBoundingBox();
          return {
            x: bbox.x1 + x10,
            y: bbox.y1 + y9,
            top: bbox.y1 + y9,
            left: bbox.x1 + x10,
            bottom: bbox.y2 + y9,
            right: bbox.x2 + x10,
            height: bbox.h,
            width: bbox.w
          };
        }
      };
      V5(virtualElt, tooltip, {
        placement: "right-end",
        middleware: [P7()]
      }).then(
        ({ x: x11, y: y10, placement }) => this.positionAt(x11, y10, placement)
      );
    }
    positionAt(x10, y9, placement) {
      this.setState({
        style: {
          flexDirection: placement.slice(-3) == "end" ? "column-reverse" : "column",
          visibility: "visible",
          left: `${x10}px`,
          top: `${y9}px`,
          zIndex: 5
        }
      });
    }
    getViewData() {
      switch (this.state.mode) {
        case "constraints": {
          return this.state.node?.data().constraints?.map?.(
            (c9) => m2`<div>${c9}</div>`
          );
        }
        case "assembly": {
          return m2`<pre>${this.state.node.data().contents}</pre>`;
        }
        case "vex": {
          return m2`<pre>${this.state.node.data().vex}</pre>`;
        }
        case "errors": {
          if (this.state.node.data().error) {
            return m2`<pre>${this.state.node.data().error}</pre>`;
          } else {
            return null;
          }
        }
        case "stdout": {
          if (this.state.node.data().stdout) {
            return m2`<pre>${this.state.node.data().stdout}</pre>`;
          } else {
            return null;
          }
        }
        case "stderr": {
          if (this.state.node.data().stderr) {
            return m2`<pre>${this.state.node.data().stderr}</pre>`;
          } else {
            return null;
          }
        }
        default:
          return null;
      }
    }
    setView(mode) {
      this.setState({ mode }, () => this.refreshPosition());
    }
    clearTooltip() {
      this.setState({ style: {
        visibility: "hidden",
        left: 0,
        top: 0,
        zIndex: 0
      } });
    }
    render(_props, state) {
      return m2`<div id="tooltip" style=${state.style}>
      <div id="tooltip-buttons">
        <button
          data-highlighted=${state.mode == "assembly"} 
          onClick=${() => this.setView("assembly")}>
          Assembly
        </button>
        <button
          data-highlighted=${state.mode == "constraints"} 
          onClick=${() => this.setView("constraints")}>
          Constraints
        </button>
        ${this.state.node?.data().vex && m2`
          <button 
            data-highlighted=${state.mode == "vex"} 
            onClick=${() => this.setView("vex")}>
            Vex IR
          </button>`}
        ${this.state.node?.data().error && m2`
          <button 
            data-highlighted=${state.mode == "errors"} 
            onClick=${() => this.setView("errors")}>
            Errors
          </button>`}
        ${this.state.node?.data().stdout && m2`
          <button 
            data-highlighted=${state.mode == "stdout"} 
            onClick=${() => this.setView("stdout")}>
            Stdout
          </button>`}
        ${this.state.node?.data().stderr && m2`
          <button 
            data-highlighted=${state.mode == "stderr"} 
            onClick=${() => this.setView("stderr")}>
            Stderr
          </button>`}
      </div>
      <div id="tooltip-data">${this.getViewData()}</div>
    </div>`;
    }
  };

  // http-url:https://cdn.jsdelivr.net/npm/diff@5.1.0/+esm
  function e18() {
  }
  function n10(e19, n11, t14, r8, i9) {
    for (var o11 = 0, l10 = n11.length, s10 = 0, a8 = 0; o11 < l10; o11++) {
      var u9 = n11[o11];
      if (u9.removed) {
        if (u9.value = e19.join(r8.slice(a8, a8 + u9.count)), a8 += u9.count, o11 && n11[o11 - 1].added) {
          var f10 = n11[o11 - 1];
          n11[o11 - 1] = n11[o11], n11[o11] = f10;
        }
      } else {
        if (!u9.added && i9) {
          var d10 = t14.slice(s10, s10 + u9.count);
          d10 = d10.map(function(e20, n12) {
            var t15 = r8[a8 + n12];
            return t15.length > e20.length ? t15 : e20;
          }), u9.value = e19.join(d10);
        } else
          u9.value = e19.join(t14.slice(s10, s10 + u9.count));
        s10 += u9.count, u9.added || (a8 += u9.count);
      }
    }
    var c9 = n11[l10 - 1];
    return l10 > 1 && "string" == typeof c9.value && (c9.added || c9.removed) && e19.equals("", c9.value) && (n11[l10 - 2].value += c9.value, n11.pop()), n11;
  }
  e18.prototype = { diff: function(e19, t14) {
    var r8 = arguments.length > 2 && void 0 !== arguments[2] ? arguments[2] : {}, i9 = r8.callback;
    "function" == typeof r8 && (i9 = r8, r8 = {}), this.options = r8;
    var o11 = this;
    function l10(e20) {
      return i9 ? (setTimeout(function() {
        i9(void 0, e20);
      }, 0), true) : e20;
    }
    e19 = this.castInput(e19), t14 = this.castInput(t14), e19 = this.removeEmpty(this.tokenize(e19));
    var s10 = (t14 = this.removeEmpty(this.tokenize(t14))).length, a8 = e19.length, u9 = 1, f10 = s10 + a8;
    r8.maxEditLength && (f10 = Math.min(f10, r8.maxEditLength));
    var d10 = [{ newPos: -1, components: [] }], c9 = this.extractCommon(d10[0], t14, e19, 0);
    if (d10[0].newPos + 1 >= s10 && c9 + 1 >= a8)
      return l10([{ value: this.join(t14), count: t14.length }]);
    function h9() {
      for (var r9 = -1 * u9; r9 <= u9; r9 += 2) {
        var i10 = void 0, f11 = d10[r9 - 1], c10 = d10[r9 + 1], h10 = (c10 ? c10.newPos : 0) - r9;
        f11 && (d10[r9 - 1] = void 0);
        var p10 = f11 && f11.newPos + 1 < s10, v11 = c10 && 0 <= h10 && h10 < a8;
        if (p10 || v11) {
          if (!p10 || v11 && f11.newPos < c10.newPos ? (i10 = { newPos: (g8 = c10).newPos, components: g8.components.slice(0) }, o11.pushComponent(i10.components, void 0, true)) : ((i10 = f11).newPos++, o11.pushComponent(i10.components, true, void 0)), h10 = o11.extractCommon(i10, t14, e19, r9), i10.newPos + 1 >= s10 && h10 + 1 >= a8)
            return l10(n10(o11, i10.components, t14, e19, o11.useLongestToken));
          d10[r9] = i10;
        } else
          d10[r9] = void 0;
      }
      var g8;
      u9++;
    }
    if (i9)
      !function e20() {
        setTimeout(function() {
          if (u9 > f10)
            return i9();
          h9() || e20();
        }, 0);
      }();
    else
      for (; u9 <= f10; ) {
        var p9 = h9();
        if (p9)
          return p9;
      }
  }, pushComponent: function(e19, n11, t14) {
    var r8 = e19[e19.length - 1];
    r8 && r8.added === n11 && r8.removed === t14 ? e19[e19.length - 1] = { count: r8.count + 1, added: n11, removed: t14 } : e19.push({ count: 1, added: n11, removed: t14 });
  }, extractCommon: function(e19, n11, t14, r8) {
    for (var i9 = n11.length, o11 = t14.length, l10 = e19.newPos, s10 = l10 - r8, a8 = 0; l10 + 1 < i9 && s10 + 1 < o11 && this.equals(n11[l10 + 1], t14[s10 + 1]); )
      l10++, s10++, a8++;
    return a8 && e19.components.push({ count: a8 }), e19.newPos = l10, s10;
  }, equals: function(e19, n11) {
    return this.options.comparator ? this.options.comparator(e19, n11) : e19 === n11 || this.options.ignoreCase && e19.toLowerCase() === n11.toLowerCase();
  }, removeEmpty: function(e19) {
    for (var n11 = [], t14 = 0; t14 < e19.length; t14++)
      e19[t14] && n11.push(e19[t14]);
    return n11;
  }, castInput: function(e19) {
    return e19;
  }, tokenize: function(e19) {
    return e19.split("");
  }, join: function(e19) {
    return e19.join("");
  } };
  var t13 = new e18();
  var o10 = /^[A-Za-z\xC0-\u02C6\u02C8-\u02D7\u02DE-\u02FF\u1E00-\u1EFF]+$/;
  var l9 = /\S/;
  var s9 = new e18();
  s9.equals = function(e19, n11) {
    return this.options.ignoreCase && (e19 = e19.toLowerCase(), n11 = n11.toLowerCase()), e19 === n11 || this.options.ignoreWhitespace && !l9.test(e19) && !l9.test(n11);
  }, s9.tokenize = function(e19) {
    for (var n11 = e19.split(/([^\S\r\n]+|[()[\]{}'"\r\n]|\b)/), t14 = 0; t14 < n11.length - 1; t14++)
      !n11[t14 + 1] && n11[t14 + 2] && o10.test(n11[t14]) && o10.test(n11[t14 + 2]) && (n11[t14] += n11[t14 + 2], n11.splice(t14 + 1, 2), t14--);
    return n11;
  };
  var f9 = new e18();
  function d9(e19, n11, t14) {
    return f9.diff(e19, n11, t14);
  }
  f9.tokenize = function(e19) {
    var n11 = [], t14 = e19.split(/(\n|\r\n)/);
    t14[t14.length - 1] || t14.pop();
    for (var r8 = 0; r8 < t14.length; r8++) {
      var i9 = t14[r8];
      r8 % 2 && !this.options.newlineIsToken ? n11[n11.length - 1] += i9 : (this.options.ignoreWhitespace && (i9 = i9.trim()), n11.push(i9));
    }
    return n11;
  };
  var h8 = new e18();
  h8.tokenize = function(e19) {
    return e19.split(/(\S.+?[.!?])(?=\s+|$)/);
  };
  var v10 = new e18();
  function m10(e19) {
    return m10 = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(e20) {
      return typeof e20;
    } : function(e20) {
      return e20 && "function" == typeof Symbol && e20.constructor === Symbol && e20 !== Symbol.prototype ? "symbol" : typeof e20;
    }, m10(e19);
  }
  v10.tokenize = function(e19) {
    return e19.split(/([{}:;,]|\s+)/);
  };
  var x9 = Object.prototype.toString;
  var L8 = new e18();
  function k8(e19, n11, t14, r8, i9) {
    var o11, l10;
    for (n11 = n11 || [], t14 = t14 || [], r8 && (e19 = r8(i9, e19)), o11 = 0; o11 < n11.length; o11 += 1)
      if (n11[o11] === e19)
        return t14[o11];
    if ("[object Array]" === x9.call(e19)) {
      for (n11.push(e19), l10 = new Array(e19.length), t14.push(l10), o11 = 0; o11 < e19.length; o11 += 1)
        l10[o11] = k8(e19[o11], n11, t14, r8, i9);
      return n11.pop(), t14.pop(), l10;
    }
    if (e19 && e19.toJSON && (e19 = e19.toJSON()), "object" === m10(e19) && null !== e19) {
      n11.push(e19), l10 = {}, t14.push(l10);
      var s10, a8 = [];
      for (s10 in e19)
        e19.hasOwnProperty(s10) && a8.push(s10);
      for (a8.sort(), o11 = 0; o11 < a8.length; o11 += 1)
        l10[s10 = a8[o11]] = k8(e19[s10], n11, t14, r8, s10);
      n11.pop(), t14.pop();
    } else
      l10 = e19;
    return l10;
  }
  L8.useLongestToken = true, L8.tokenize = f9.tokenize, L8.castInput = function(e19) {
    var n11 = this.options, t14 = n11.undefinedReplacement, r8 = n11.stringifyReplacer, i9 = void 0 === r8 ? function(e20, n12) {
      return void 0 === n12 ? t14 : n12;
    } : r8;
    return "string" == typeof e19 ? e19 : JSON.stringify(k8(e19, null, null, i9), i9, "  ");
  }, L8.equals = function(n11, t14) {
    return e18.prototype.equals.call(L8, n11.replace(/,([\r\n])/g, "$1"), t14.replace(/,([\r\n])/g, "$1"));
  };
  var b9 = new e18();
  b9.tokenize = function(e19) {
    return e19.slice();
  }, b9.join = b9.removeEmpty = function(e19) {
    return e19;
  };

  // diffPanel.js
  var DiffPanel = class extends m {
    constructor() {
      super();
      this.state = {
        mode: null
      };
    }
    toggleMode(mode) {
      if (this.state.mode == mode) {
        this.setState({ mode: null });
      } else {
        this.setState({ mode });
      }
    }
    setLeftFocus(leftFocus) {
      this.setState({ leftFocus });
      if (this.state.rightFocus)
        this.diffAssemblyWith(leftFocus, this.state.rightFocus);
    }
    setRightFocus(rightFocus) {
      this.setState({ rightFocus });
      if (this.state.leftFocus)
        this.diffAssemblyWith(this.state.leftFocus, rightFocus);
    }
    setBothFoci(leftFocus, rightFocus) {
      this.setState({ leftFocus, rightFocus });
      this.diffAssemblyWith(leftFocus, rightFocus);
    }
    resetLeftFocus(leftFocus) {
      this.setState({
        rightFocus: null,
        rightAssemblyDiff: null,
        leftAssemblyDiff: null,
        leftFocus
      });
    }
    resetRightFocus(rightFocus) {
      this.setState({
        leftFocus: null,
        rightAssemblyDiff: null,
        leftAssemblyDiff: null,
        rightFocus
      });
    }
    diffAssemblyWith(leftFocus, rightFocus) {
      const leftLines = leftFocus.data().assembly.split("\n");
      const rightLines = rightFocus.data().assembly.split("\n");
      const diffs = d9(leftFocus.data().assembly, rightFocus.data().assembly, {
        comparator(l10, r8) {
          return l10.substring(6) == r8.substring(6);
        }
      });
      let renderedRight = [];
      let renderedLeft = [];
      let curLeft = 0;
      let curRight = 0;
      for (const diff of diffs) {
        let hunkRight;
        let hunkLeft;
        if (diff?.added) {
          hunkRight = m2`<span class="hunkAdded">${diff.value}</span>`;
          hunkLeft = m2`<span>${Array(diff.count).fill("\n").join("")}</span>`;
          curRight += diff.count;
        } else if (diff?.removed) {
          hunkLeft = m2`<span class="hunkRemoved">${diff.value}</span>`;
          hunkRight = m2`<span>${Array(diff.count).fill("\n").join("")}</span>`;
          curLeft += diff.count;
        } else {
          const leftPiece = [];
          const rightPiece = [];
          for (let i9 = 0; i9 < diff.count; i9++) {
            leftPiece.push(leftLines[curLeft] + "\n");
            rightPiece.push(rightLines[curRight] + "\n");
            curRight++;
            curLeft++;
          }
          hunkRight = m2`<span>${rightPiece}</span>`;
          hunkLeft = m2`<span>${leftPiece}</span>`;
        }
        renderedRight.push(hunkRight);
        renderedLeft.push(hunkLeft);
      }
      this.setState({
        leftAssemblyDiff: renderedLeft,
        rightAssemblyDiff: renderedRight
      });
    }
    getLeftFocusAssembly() {
      return this.state.leftAssemblyDiff || this.state.leftFocus?.data().assembly;
    }
    getRightFocusAssembly() {
      return this.state.rightAssemblyDiff || this.state.rightFocus?.data().assembly;
    }
    getRegisterDifference() {
      const rightId = this.state.rightFocus.id();
      const registers = [];
      const rdiffs = this.state.leftFocus.data().compatibilities[rightId].regdiff;
      for (const reg in rdiffs) {
        registers.push(m2`
        <span class="grid-diff-left">${rdiffs[reg][0]}</span>
        <span class="grid-diff-label">${reg}</span>
        <span class="grid-diff-right">${rdiffs[reg][1]}</span>`);
      }
      if (registers.length > 0)
        return registers;
      else
        return m2`<span class="no-difference">no register differences detected ✓</span>`;
    }
    getMemoryDifference() {
      const rightId = this.state.rightFocus.id();
      const addresses = [];
      const adiffs = this.state.leftFocus.data().compatibilities[rightId].memdiff;
      for (const reg in adiffs) {
        addresses.push(m2`
        <span class="grid-diff-left">${adiffs[reg][0]}</span>
        <span class="grid-diff-label">${reg}</span>
        <span class="grid-diff-right">${adiffs[reg][1]}</span>`);
      }
      if (addresses.length > 0)
        return addresses;
      else
        return m2`<span class="no-difference">no memory differences detected ✓</span>`;
    }
    getConcretion() {
      const rightId = this.state.rightFocus.id();
      const examples = [];
      const concretions = this.state.leftFocus.data().compatibilities[rightId].conc_args;
      for (const concretion of concretions) {
        examples.push(m2`
        <pre class="concrete-example">${JSON.stringify(concretion, void 0, 2)}</pre>
      `);
      }
      return m2`<div id="concretion-header">
      Viewing ${concretions.length} concrete input examples
    </div>
    <div id="concretion-data">
      ${examples}
    </div>`;
    }
    render(props, state) {
      const assemblyAvailable = state.leftFocus || state.rightFocus;
      const registersAvailable = state.leftFocus && state.rightFocus && state.leftFocus.data().compatibilities[state.rightFocus.id()].regdiff;
      const memoryAvailable = state.leftFocus && state.rightFocus && state.leftFocus.data().compatibilities[state.rightFocus.id()].memdiff;
      const concretionAvailable = state.leftFocus && state.rightFocus && state.leftFocus.data().compatibilities[state.rightFocus.id()].conc_args;
      return m2`<div id="diff-panel" onMouseEnter=${props.onMouseEnter}>
      <div>
        <button 
          disabled=${!assemblyAvailable}
          onClick=${() => this.toggleMode("assembly")}>
          Assembly
        </button>
        <button 
          disabled=${!memoryAvailable}
          onClick=${() => this.toggleMode("memory")}>
          Memory
        </button>
        <button disabled=${!registersAvailable}
          onClick=${() => this.toggleMode("registers")}>
          Registers
        </button>
        <button disabled=${!concretionAvailable}
          onClick=${() => this.toggleMode("concretions")}>
          Concretions
        </button>
      </div>
      ${state.mode == "assembly" && assemblyAvailable && m2`
        <div id="asm-diff-data">
          <pre id="asmViewLeft">
          ${this.getLeftFocusAssembly()}
          </pre>
          <pre id="asmViewRight">
          ${this.getRightFocusAssembly()}
          </pre>
        </div>`}
      ${state.mode == "registers" && registersAvailable && m2`
        <div id="grid-diff-data">
          ${this.getRegisterDifference()}
        </div>`}
      ${state.mode == "memory" && memoryAvailable && m2`
        <div id="grid-diff-data">
          ${this.getMemoryDifference()}
        </div>`}
      ${state.mode == "concretions" && concretionAvailable && this.getConcretion()}
      </div>`;
    }
  };

  // menuBar.js
  var Menu = class extends m {
    constructor() {
      super();
      this.button = _();
      this.options = _();
    }
    componentDidUpdate() {
      if (this.props.open == this.props.title) {
        V5(this.button.current, this.options.current, {
          placement: "bottom-start"
        }).then(({ x: x10, y: y9 }) => {
          this.options.current.style.left = `${x10}px`;
          this.options.current.style.top = `${y9}px`;
        });
      }
    }
    toggleOpen() {
      if (this.props.open != this.props.title) {
        this.props.setOpen(this.props.title);
      } else {
        this.props.setOpen(null);
      }
    }
    render(props) {
      const optionStyle = {
        position: "absolute",
        display: "block",
        backgroundColor: "#e1e1e1"
      };
      const menuStyle = {
        backgroundColor: props.open === props.title ? "#e1e1e1" : "white"
      };
      return m2`
      <button 
        style=${menuStyle} 
        ref=${this.button} 
        onClick=${() => this.toggleOpen()}
        onMouseEnter=${() => props.open && props.setOpen(props.title)}>
        ${props.title}
      </button>
      ${props.open == props.title && m2`
        <div style=${optionStyle} ref=${this.options} class="options-wrapper">
          ${props.children}
        </div>`}`;
    }
  };
  function noMemoryDiffs(leaf, other) {
    const comparison = leaf.data().compatibilities[other.id()];
    if (Object.keys(comparison.memdiff).length)
      return false;
    else
      return noErrors(leaf, other);
  }
  function noRegisterDiffs(leaf, other) {
    const comparison = leaf.data().compatibilities[other.id()];
    if (Object.keys(comparison.regdiff).length)
      return false;
    else
      return noErrors(leaf, other);
  }
  function noErrors(leaf, other) {
    if (leaf.data().error || other.data().error)
      return false;
    else
      return true;
  }
  function noStdDiffs(leaf, other) {
    if (leaf.data().stdout != other.data().stdout || leaf.data().stderr != other.data().stderr)
      return false;
    else
      return noErrors(leaf, other);
  }
  var MenuBar = class extends m {
    constructor() {
      super();
      this.state = {
        open: null
      };
    }
    componentDidMount() {
      this.globalClickListener = (ev) => this.handleGlobalClick(ev);
      this.closeListener = () => this.setOpen(null);
      window.addEventListener("blur", this.closeListener);
      window.addEventListener("mousedown", this.globalClickListener);
    }
    componentWillUnmount() {
      window.removeEventListener("blur", this.closeListener);
      window.removeEventListener("mousedown", this.globalClickListener);
    }
    setOpen(open) {
      this.setState({ open });
    }
    handleGlobalClick() {
      if (this.state.open) {
        this.setState({ open: null });
      }
    }
    handleLocalClick(ev) {
      if (this.state.open) {
        ev.stopPropagation();
      }
    }
    prune(test) {
      this.props.prune(test);
      this.setOpen(null);
    }
    setTidiness(level) {
      this.props.setTidiness(level);
      this.setOpen(null);
    }
    resetLayout() {
      this.props.resetLayout();
      this.setOpen(null);
    }
    render(props, state) {
      return m2`<div id="menubar"
        onMousedown=${(ev) => this.handleLocalClick(ev)}
      >
      <${Menu} open=${state.open}
        title="View"
        setOpen=${(o11) => this.setOpen(o11)}>
        <option 
          onClick=${() => this.setTidiness("untidy")}
          data-selected=${props.tidiness == "untidy"}>
            Show All Blocks
        </option>
        <option 
          onClick=${() => this.setTidiness("tidy")}
          data-selected=${props.tidiness == "tidy"}>
            Merge Unless Constaints Change
        </option>
        <option 
          onClick=${() => this.setTidiness("very-tidy")}
          data-selected=${props.tidiness == "very-tidy"}>
            Merge Unless Branching Occurs
        </option>
      <//>
      <${Menu} open=${state.open}
        title="Prune"
        setOpen=${(o11) => this.setOpen(o11)}>
        <option onClick=${() => this.prune(noMemoryDiffs)}>
            Completed Branches with Identical Memory
        </option>
        <option onClick=${() => this.prune(noRegisterDiffs)}>
            Completed Branches with Identical Register Contents 
        </option>
        <option onClick=${() => this.prune(noStdDiffs)}>
            Completed Branches with Identical Stdout/Stderr
        </option>
        <option onClick=${() => this.prune(noErrors)}>
            All Completed (Error-free) Branches
        </option>
      <//>
      <${Menu} open=${state.open}
        title="Layout"
        setOpen=${(o11) => this.setOpen(o11)}>
        <option onClick=${() => this.resetLayout()}>
            Reset
        </option>
      <//>
    </div>`;
    }
  };

  // focusMixin.js
  var focusMixin = {
    focus(loci) {
      if (!loci)
        return;
      this.loci = loci;
      for (const locus of loci) {
        if (locus.removed())
          continue;
        if (loci.length > 1) {
          locus.addClass("availablePath");
        } else {
          locus.addClass("pathHighlight");
        }
        locus.predecessors().addClass("pathHighlight");
      }
      return this;
    },
    refocus() {
      this.elements().removeClass("pathHighlight").removeClass("availablePath");
      this.focus(this.loci);
      return this;
    },
    blur() {
      this.loci = null;
      this.elements().removeClass("pathHighlight").removeClass("availablePath");
      return this;
    }
  };

  // diffStyle.js
  var diffStyle = [
    {
      selector: "node",
      style: {
        // 'background-image': (ele) => { return makeSvg(ele).svg },
        // 'width': (ele) => { return makeSvg(ele).width},
        // 'height': (ele) => { return makeSvg(ele).height},
        "shape": "round-rectangle",
        "background-color": (elt) => {
          if (elt.data().error) {
            return "#facdcd";
          } else {
            return "#ededed";
          }
        },
        "border-color": "#ccc",
        "border-width": (elt) => {
          if (elt.outgoers().length == 0 && !elt.data().error) {
            return "5px";
          } else {
            return "0px";
          }
        }
      }
    },
    {
      selector: "edge",
      style: {
        "width": 3,
        "line-color": "#ccc",
        "target-arrow-color": "#ccc",
        "target-arrow-shape": "triangle",
        // 'arrow-scale': '2',
        "curve-style": "bezier"
      }
    },
    {
      selector: "edge.pathHighlight",
      style: {
        "width": 3,
        "line-color": "#666",
        "target-arrow-color": "#666",
        "target-arrow-shape": "triangle",
        "z-compound-depth": "top",
        // 'arrow-scale': '2',
        "curve-style": "bezier"
      }
    },
    {
      selector: "node.pathHighlight",
      style: {
        "border-width": "0px",
        "background-color": (elt) => {
          if (elt.data().error) {
            return "#d00";
          } else {
            return "#666";
          }
        }
      }
    },
    {
      selector: "node.availablePath",
      style: {
        "border-width": "5px",
        "border-color": "#666"
      }
    }
  ];

  // graph-tidy.js
  function tidyGraph(graph, opts) {
    const root = graph.nodes().roots();
    tidyChildren(root, opts);
  }
  function constraintsEq(c1, c22) {
    if (c1.length != c22.length)
      return false;
    for (let i9 = 0; i9 < c1.length; i9++) {
      if (c1[i9] != c22[i9])
        return false;
    }
    return true;
  }
  function tidyChildren(node, { mergeConstraints }) {
    let candidates = [node];
    let next = [];
    while (candidates.length > 0) {
      for (const candidate of candidates) {
        const out = candidate.outgoers("node");
        const constraints1 = out[0]?.data().constraints;
        const constraints2 = candidate.data().constraints;
        if (out.length == 1 && (mergeConstraints || constraintsEq(constraints1, constraints2))) {
          out[0].data().contents = candidate.data().contents + "\n" + out[0].data().contents;
          if (candidate.data().vex) {
            out[0].data().vex = candidate.data().vex + "\n" + out[0].data().vex;
          }
          for (const parent of candidate.incomers("node")) {
            const edgeData = {
              id: `${parent.id()}-${out[0].id()}`,
              source: parent.id(),
              target: out[0].id()
            };
            node.cy().add({ group: "edges", data: edgeData });
          }
          candidate.remove();
          next.push(out[0]);
        } else {
          for (const baby of out) {
            next.push(baby);
          }
        }
      }
      candidates = next;
      next = [];
    }
  }
  function removeBranch(node) {
    let target;
    while (node.outgoers("node").length == 0 && node.incomers("node").length > 0) {
      target = node;
      node = node.incomers("node")[0];
      target.remove();
    }
  }

  // cozy-viz.js
  var standardLayout = { name: "breadthfirst", directed: true, spacingFactor: 2 };
  var App = class extends m {
    constructor() {
      super();
      this.state = {
        status: null,
        // idle
        tidiness: "untidy"
        // we're not yet tidying anything
      };
      this.cy1 = _();
      this.cy2 = _();
      this.tooltip = _();
      this.diffPanel = _();
      window.app = this;
    }
    componentDidMount() {
      const urlParams = new URLSearchParams(window.location.search);
      const isServedPre = urlParams.get("pre");
      const isServedPost = urlParams.get("post");
      if (isServedPre) {
        fetch(isServedPre).then((rslt) => rslt.json()).then((raw) => {
          const obj = JSON.parse(raw);
          if (!obj.elements)
            throw new Error("Malformed post-patch JSON");
          this.mountToCytoscape(obj, this.cy1);
        }).catch((e19) => console.error(e19));
      }
      if (isServedPost) {
        fetch(isServedPost).then((rslt) => rslt.json()).then((raw) => {
          const obj = JSON.parse(raw);
          if (!obj.elements)
            throw new Error("Malformed post-patch JSON");
          this.mountToCytoscape(obj, this.cy2);
        }).catch((e19) => console.error(e19));
      }
    }
    handleClick(ev) {
      if (!this.cy1.cy || !this.cy2.cy) {
        alert("Please load both graphs before attempting comparison.");
        return;
      }
      const isLeft = ev.target.cy() == this.cy1.cy;
      const self2 = isLeft ? this.cy1.cy : this.cy2.cy;
      const other = isLeft ? this.cy2.cy : this.cy1.cy;
      this.tooltip.current.attachTo(ev.target);
      if (self2.loci?.length > 1 && self2.loci.includes(ev.target)) {
        self2.blur().focus(ev.target);
        if (isLeft)
          this.diffPanel.current.setLeftFocus(ev.target);
        else
          this.diffPanel.current.setRightFocus(ev.target);
      } else {
        self2.blur().focus([ev.target]);
        other.blur().focus(other.nodes().filter((node) => +node.data().id in ev.target.data().compatibilities));
        if (Object.keys(ev.target.data().compatibilities).length == 1) {
          const theId = Object.keys(ev.target.data().compatibilities)[0];
          if (isLeft)
            this.diffPanel.current.setBothFoci(ev.target, other.nodes(`#${theId}`));
          else
            this.diffPanel.current.setBothFoci(other.nodes(`#${theId}`), ev.target);
        } else {
          if (isLeft)
            this.diffPanel.current.resetLeftFocus(ev.target);
          else
            this.diffPanel.current.resetRightFocus(ev.target);
        }
      }
    }
    refresh() {
      this.cy1.cy.json({ elements: JSON.parse(this.cy1.orig).elements });
      this.cy2.cy.json({ elements: JSON.parse(this.cy2.orig).elements });
      this.cy1.cy.refocus().fit();
      this.cy2.cy.refocus().fit();
      this.setState({ status: null });
    }
    tidy(opts) {
      tidyGraph(this.cy1.cy, opts);
      tidyGraph(this.cy2.cy, opts);
      this.cy1.cy.layout(standardLayout).run();
      this.cy2.cy.layout(standardLayout).run();
      this.cy1.cy.refocus().fit();
      this.cy2.cy.refocus().fit();
      this.setState({ status: null });
    }
    async handleDrop(ev, ref) {
      ev.stopPropagation();
      ev.preventDefault();
      ev.target.classList.remove("dragHover");
      const file = ev.dataTransfer.files[0];
      const raw = await file.text().then((text) => JSON.parse(text));
      this.mountToCytoscape(raw, ref);
    }
    handleDragover(ev) {
      ev.stopPropagation();
      ev.preventDefault();
      ev.target.classList.add("dragHover");
    }
    handleDragleave(ev) {
      ev.stopPropagation();
      ev.preventDefault();
      ev.target.classList.remove("dragHover");
    }
    mountToCytoscape(raw, ref) {
      const cy = Pl({
        style: diffStyle,
        elements: raw.elements
      });
      cy.mount(ref.current);
      Object.assign(cy, focusMixin);
      cy.layout(standardLayout).run();
      for (const leaf of [...cy.nodes().leaves()]) {
        let assembly = "";
        for (const node of leaf.predecessors("node").reverse()) {
          assembly += node.data().contents + "\n";
        }
        assembly += leaf.data().contents;
        leaf.data().assembly = assembly;
      }
      cy.nodes().map((node) => this.initializeNode(node, cy));
      cy.on("add", (ev) => {
        if (ev.target.group() === "nodes") {
          this.initializeNode(ev.target, cy);
        }
      });
      cy.on("click", (ev) => {
        if (!ev.target.group) {
          this.batch(() => {
            this.cy1.cy.blur();
            this.cy2.cy.blur();
            this.tooltip.current.clearTooltip();
          });
        }
      });
      ref.cy = cy;
      ref.orig = JSON.stringify(cy.json());
      this.setState({ status: null });
    }
    initializeNode(node, cy) {
      node.ungrabify();
      node.on("mouseout", () => {
        cy.container().style.cursor = "default";
      });
      node.on("mouseover", (ev) => {
        if (ev.target.outgoers().length == 0) {
          cy.container().style.cursor = "pointer";
        }
        if (cy.loci && !ev.target.hasClass("pathHighlight"))
          return;
        this.tooltip.current.attachTo(ev.target);
      });
      node.leaves().on(
        "click",
        (ev) => this.handleClick(ev)
      );
    }
    startRender(method) {
      this.setState({ status: "rendering" }, method);
    }
    batch(cb) {
      this.cy1.cy.startBatch();
      this.cy2.cy.startBatch();
      cb();
      this.cy1.cy.endBatch();
      this.cy2.cy.endBatch();
    }
    async setTidiness(tidiness) {
      await new Promise((r8) => setTimeout(r8, 50));
      switch (tidiness) {
        case "untidy": {
          this.refresh();
          break;
        }
        case "tidy": {
          if (this.state.tidiness == "very-tidy") {
            this.batch(() => {
              this.refresh();
              this.tidy({});
            });
          } else
            this.tidy({});
          break;
        }
        case "very-tidy": {
          this.batch(() => {
            this.refresh();
            this.tidy({ mergeConstraints: true });
          });
          break;
        }
      }
      this.setState({ tidiness, status: null });
    }
    resetLayout() {
      this.batch(() => {
        this.cy1.cy.layout(standardLayout).run();
        this.cy2.cy.layout(standardLayout).run();
      });
    }
    // prune all branches whose compatibilities all fail some test (e.g. all have
    // the same memory contents as the given branch)
    prune(test) {
      const leaves1 = this.cy1.cy.nodes().leaves();
      const leaves2 = this.cy2.cy.nodes().leaves();
      for (const leaf of [...leaves1, ...leaves2]) {
        let flag = true;
        let other = leaf.cy() == this.cy1.cy ? this.cy2.cy : this.cy1.cy;
        for (const key in leaf.data().compatibilities) {
          const otherleaf = other.nodes(`#${key}`);
          if (otherleaf.length == 0)
            continue;
          flag &&= test(leaf, otherleaf);
        }
        if (flag)
          removeBranch(leaf);
      }
      this.cy1.cy.refocus();
      this.cy2.cy.refocus();
    }
    render(_props, state) {
      return m2`
      <${Tooltip} ref=${this.tooltip}/>
      <${MenuBar} 
        setTidiness=${(level) => this.startRender(() => this.setTidiness(level))}
        prune=${(relation) => this.prune(relation)}
        resetLayout=${() => this.resetLayout()}
        tidiness=${state.tidiness}/>
      <div id="main-view">
        <div 
          onMouseEnter=${() => this.tooltip.current.clearTooltip()} 
          onDragover=${(ev) => this.handleDragover(ev)}
          onDragleave=${(ev) => this.handleDragleave(ev)}
          onDrop=${(ev) => this.startRender(() => this.handleDrop(ev, this.cy1))} 
          ref=${this.cy1} id="cy1">
            <span id="labelLeft">prepatch</span>
        </div>
        <div 
          onMouseEnter=${() => this.tooltip.current.clearTooltip()} 
          onDragover=${(ev) => this.handleDragover(ev)}
          onDragleave=${(ev) => this.handleDragleave(ev)}
          onDrop=${(ev) => this.startRender(() => this.handleDrop(ev, this.cy2))}
          ref=${this.cy2} id="cy2">
            <span id="labelRight">postpatch</span>
        </div>
      </div>
      <${DiffPanel} 
        onMouseEnter=${() => this.tooltip.current.clearTooltip()} 
        ref=${this.diffPanel}/>
      ${state.status == "rendering" && m2`<span id="render-indicator">rendering...</span>`}
    `;
    }
  };
  B(m2`<${App}/>`, document.body);
})();
/*!
Embeddable Minimum Strictly-Compliant Promises/A+ 1.1.1 Thenable
Copyright (c) 2013-2014 Ralf S. Engelschall (http://engelschall.com)
Licensed under The MIT License (http://opensource.org/licenses/MIT)
*/
/*! Bezier curve function generator. Copyright Gaetan Renaudeau. MIT License: http://en.wikipedia.org/wiki/MIT_License */
/*! Runge-Kutta spring physics function generator. Adapted from Framer.js, copyright Koen Bok. MIT License: http://en.wikipedia.org/wiki/MIT_License */
