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
  var c;
  var s;
  var a;
  var h = {};
  var v = [];
  var p = /acit|ex(?:s|g|n|p|$)|rph|grid|ows|mnc|ntw|ine[ch]|zoo|^ord|itera/i;
  var y = Array.isArray;
  function d(n13, l11) {
    for (var u10 in l11)
      n13[u10] = l11[u10];
    return n13;
  }
  function w(n13) {
    n13 && n13.parentNode && n13.parentNode.removeChild(n13);
  }
  function _(l11, u10, t17) {
    var i11, o13, r10, f11 = {};
    for (r10 in u10)
      "key" == r10 ? i11 = u10[r10] : "ref" == r10 ? o13 = u10[r10] : f11[r10] = u10[r10];
    if (arguments.length > 2 && (f11.children = arguments.length > 3 ? n.call(arguments, 2) : t17), "function" == typeof l11 && null != l11.defaultProps)
      for (r10 in l11.defaultProps)
        void 0 === f11[r10] && (f11[r10] = l11.defaultProps[r10]);
    return g(l11, f11, i11, o13, null);
  }
  function g(n13, t17, i11, o13, r10) {
    var f11 = { type: n13, props: t17, key: i11, ref: o13, __k: null, __: null, __b: 0, __e: null, __d: void 0, __c: null, constructor: void 0, __v: null == r10 ? ++u : r10, __i: -1, __u: 0 };
    return null == r10 && null != l.vnode && l.vnode(f11), f11;
  }
  function m() {
    return { current: null };
  }
  function b(n13) {
    return n13.children;
  }
  function k(n13, l11) {
    this.props = n13, this.context = l11;
  }
  function x(n13, l11) {
    if (null == l11)
      return n13.__ ? x(n13.__, n13.__i + 1) : null;
    for (var u10; l11 < n13.__k.length; l11++)
      if (null != (u10 = n13.__k[l11]) && null != u10.__e)
        return u10.__e;
    return "function" == typeof n13.type ? x(n13) : null;
  }
  function C(n13) {
    var l11, u10;
    if (null != (n13 = n13.__) && null != n13.__c) {
      for (n13.__e = n13.__c.base = null, l11 = 0; l11 < n13.__k.length; l11++)
        if (null != (u10 = n13.__k[l11]) && null != u10.__e) {
          n13.__e = n13.__c.base = u10.__e;
          break;
        }
      return C(n13);
    }
  }
  function S(n13) {
    (!n13.__d && (n13.__d = true) && i.push(n13) && !M.__r++ || o !== l.debounceRendering) && ((o = l.debounceRendering) || r)(M);
  }
  function M() {
    var n13, u10, t17, o13, r10, e22, c10, s11;
    for (i.sort(f); n13 = i.shift(); )
      n13.__d && (u10 = i.length, o13 = void 0, e22 = (r10 = (t17 = n13).__v).__e, c10 = [], s11 = [], t17.__P && ((o13 = d({}, r10)).__v = r10.__v + 1, l.vnode && l.vnode(o13), O(t17.__P, o13, r10, t17.__n, t17.__P.namespaceURI, 32 & r10.__u ? [e22] : null, c10, null == e22 ? x(r10) : e22, !!(32 & r10.__u), s11), o13.__v = r10.__v, o13.__.__k[o13.__i] = o13, j(c10, o13, s11), o13.__e != e22 && C(o13)), i.length > u10 && i.sort(f));
    M.__r = 0;
  }
  function P(n13, l11, u10, t17, i11, o13, r10, f11, e22, c10, s11) {
    var a10, p10, y10, d12, w10, _7 = t17 && t17.__k || v, g9 = l11.length;
    for (u10.__d = e22, $(u10, l11, _7), e22 = u10.__d, a10 = 0; a10 < g9; a10++)
      null != (y10 = u10.__k[a10]) && (p10 = -1 === y10.__i ? h : _7[y10.__i] || h, y10.__i = a10, O(n13, y10, p10, i11, o13, r10, f11, e22, c10, s11), d12 = y10.__e, y10.ref && p10.ref != y10.ref && (p10.ref && E(p10.ref, null, y10), s11.push(y10.ref, y10.__c || d12, y10)), null == w10 && null != d12 && (w10 = d12), 65536 & y10.__u || p10.__k === y10.__k ? e22 = I(y10, e22, n13) : "function" == typeof y10.type && void 0 !== y10.__d ? e22 = y10.__d : d12 && (e22 = d12.nextSibling), y10.__d = void 0, y10.__u &= -196609);
    u10.__d = e22, u10.__e = w10;
  }
  function $(n13, l11, u10) {
    var t17, i11, o13, r10, f11, e22 = l11.length, c10 = u10.length, s11 = c10, a10 = 0;
    for (n13.__k = [], t17 = 0; t17 < e22; t17++)
      null != (i11 = l11[t17]) && "boolean" != typeof i11 && "function" != typeof i11 ? (r10 = t17 + a10, (i11 = n13.__k[t17] = "string" == typeof i11 || "number" == typeof i11 || "bigint" == typeof i11 || i11.constructor == String ? g(null, i11, null, null, null) : y(i11) ? g(b, { children: i11 }, null, null, null) : void 0 === i11.constructor && i11.__b > 0 ? g(i11.type, i11.props, i11.key, i11.ref ? i11.ref : null, i11.__v) : i11).__ = n13, i11.__b = n13.__b + 1, o13 = null, -1 !== (f11 = i11.__i = L(i11, u10, r10, s11)) && (s11--, (o13 = u10[f11]) && (o13.__u |= 131072)), null == o13 || null === o13.__v ? (-1 == f11 && a10--, "function" != typeof i11.type && (i11.__u |= 65536)) : f11 !== r10 && (f11 == r10 - 1 ? a10-- : f11 == r10 + 1 ? a10++ : (f11 > r10 ? a10-- : a10++, i11.__u |= 65536))) : i11 = n13.__k[t17] = null;
    if (s11)
      for (t17 = 0; t17 < c10; t17++)
        null != (o13 = u10[t17]) && 0 == (131072 & o13.__u) && (o13.__e == n13.__d && (n13.__d = x(o13)), N(o13, o13));
  }
  function I(n13, l11, u10) {
    var t17, i11;
    if ("function" == typeof n13.type) {
      for (t17 = n13.__k, i11 = 0; t17 && i11 < t17.length; i11++)
        t17[i11] && (t17[i11].__ = n13, l11 = I(t17[i11], l11, u10));
      return l11;
    }
    n13.__e != l11 && (l11 && n13.type && !u10.contains(l11) && (l11 = x(n13)), u10.insertBefore(n13.__e, l11 || null), l11 = n13.__e);
    do {
      l11 = l11 && l11.nextSibling;
    } while (null != l11 && 8 === l11.nodeType);
    return l11;
  }
  function L(n13, l11, u10, t17) {
    var i11 = n13.key, o13 = n13.type, r10 = u10 - 1, f11 = u10 + 1, e22 = l11[u10];
    if (null === e22 || e22 && i11 == e22.key && o13 === e22.type && 0 == (131072 & e22.__u))
      return u10;
    if (("function" != typeof o13 || o13 === b || i11) && t17 > (null != e22 && 0 == (131072 & e22.__u) ? 1 : 0))
      for (; r10 >= 0 || f11 < l11.length; ) {
        if (r10 >= 0) {
          if ((e22 = l11[r10]) && 0 == (131072 & e22.__u) && i11 == e22.key && o13 === e22.type)
            return r10;
          r10--;
        }
        if (f11 < l11.length) {
          if ((e22 = l11[f11]) && 0 == (131072 & e22.__u) && i11 == e22.key && o13 === e22.type)
            return f11;
          f11++;
        }
      }
    return -1;
  }
  function T(n13, l11, u10) {
    "-" === l11[0] ? n13.setProperty(l11, null == u10 ? "" : u10) : n13[l11] = null == u10 ? "" : "number" != typeof u10 || p.test(l11) ? u10 : u10 + "px";
  }
  function A(n13, l11, u10, t17, i11) {
    var o13;
    n:
      if ("style" === l11) {
        if ("string" == typeof u10)
          n13.style.cssText = u10;
        else {
          if ("string" == typeof t17 && (n13.style.cssText = t17 = ""), t17)
            for (l11 in t17)
              u10 && l11 in u10 || T(n13.style, l11, "");
          if (u10)
            for (l11 in u10)
              t17 && u10[l11] === t17[l11] || T(n13.style, l11, u10[l11]);
        }
      } else if ("o" === l11[0] && "n" === l11[1])
        o13 = l11 !== (l11 = l11.replace(/(PointerCapture)$|Capture$/i, "$1")), l11 = l11.toLowerCase() in n13 || "onFocusOut" === l11 || "onFocusIn" === l11 ? l11.toLowerCase().slice(2) : l11.slice(2), n13.l || (n13.l = {}), n13.l[l11 + o13] = u10, u10 ? t17 ? u10.u = t17.u : (u10.u = e, n13.addEventListener(l11, o13 ? s : c, o13)) : n13.removeEventListener(l11, o13 ? s : c, o13);
      else {
        if ("http://www.w3.org/2000/svg" == i11)
          l11 = l11.replace(/xlink(H|:h)/, "h").replace(/sName$/, "s");
        else if ("width" != l11 && "height" != l11 && "href" != l11 && "list" != l11 && "form" != l11 && "tabIndex" != l11 && "download" != l11 && "rowSpan" != l11 && "colSpan" != l11 && "role" != l11 && "popover" != l11 && l11 in n13)
          try {
            n13[l11] = null == u10 ? "" : u10;
            break n;
          } catch (n14) {
          }
        "function" == typeof u10 || (null == u10 || false === u10 && "-" !== l11[4] ? n13.removeAttribute(l11) : n13.setAttribute(l11, "popover" == l11 && 1 == u10 ? "" : u10));
      }
  }
  function F(n13) {
    return function(u10) {
      if (this.l) {
        var t17 = this.l[u10.type + n13];
        if (null == u10.t)
          u10.t = e++;
        else if (u10.t < t17.u)
          return;
        return l.event && (u10 = l.event(u10)), "handleEvent" in t17 ? t17.handleEvent(u10) : t17(u10);
      }
    };
  }
  function O(n13, u10, t17, i11, o13, r10, f11, e22, c10, s11) {
    var a10, h10, v12, p10, w10, _7, g9, m12, x11, C9, S8, M9, $8, I8, H8, L10, T9 = u10.type;
    if (void 0 !== u10.constructor)
      return null;
    128 & t17.__u && (c10 = !!(32 & t17.__u), r10 = [e22 = u10.__e = t17.__e]), (a10 = l.__b) && a10(u10);
    n:
      if ("function" == typeof T9)
        try {
          if (m12 = u10.props, x11 = "prototype" in T9 && T9.prototype.render, C9 = (a10 = T9.contextType) && i11[a10.__c], S8 = a10 ? C9 ? C9.props.value : a10.__ : i11, t17.__c ? g9 = (h10 = u10.__c = t17.__c).__ = h10.__E : (x11 ? u10.__c = h10 = new T9(m12, S8) : (u10.__c = h10 = new k(m12, S8), h10.constructor = T9, h10.render = V), C9 && C9.sub(h10), h10.props = m12, h10.state || (h10.state = {}), h10.context = S8, h10.__n = i11, v12 = h10.__d = true, h10.__h = [], h10._sb = []), x11 && null == h10.__s && (h10.__s = h10.state), x11 && null != T9.getDerivedStateFromProps && (h10.__s == h10.state && (h10.__s = d({}, h10.__s)), d(h10.__s, T9.getDerivedStateFromProps(m12, h10.__s))), p10 = h10.props, w10 = h10.state, h10.__v = u10, v12)
            x11 && null == T9.getDerivedStateFromProps && null != h10.componentWillMount && h10.componentWillMount(), x11 && null != h10.componentDidMount && h10.__h.push(h10.componentDidMount);
          else {
            if (x11 && null == T9.getDerivedStateFromProps && m12 !== p10 && null != h10.componentWillReceiveProps && h10.componentWillReceiveProps(m12, S8), !h10.__e && (null != h10.shouldComponentUpdate && false === h10.shouldComponentUpdate(m12, h10.__s, S8) || u10.__v === t17.__v)) {
              for (u10.__v !== t17.__v && (h10.props = m12, h10.state = h10.__s, h10.__d = false), u10.__e = t17.__e, u10.__k = t17.__k, u10.__k.some(function(n14) {
                n14 && (n14.__ = u10);
              }), M9 = 0; M9 < h10._sb.length; M9++)
                h10.__h.push(h10._sb[M9]);
              h10._sb = [], h10.__h.length && f11.push(h10);
              break n;
            }
            null != h10.componentWillUpdate && h10.componentWillUpdate(m12, h10.__s, S8), x11 && null != h10.componentDidUpdate && h10.__h.push(function() {
              h10.componentDidUpdate(p10, w10, _7);
            });
          }
          if (h10.context = S8, h10.props = m12, h10.__P = n13, h10.__e = false, $8 = l.__r, I8 = 0, x11) {
            for (h10.state = h10.__s, h10.__d = false, $8 && $8(u10), a10 = h10.render(h10.props, h10.state, h10.context), H8 = 0; H8 < h10._sb.length; H8++)
              h10.__h.push(h10._sb[H8]);
            h10._sb = [];
          } else
            do {
              h10.__d = false, $8 && $8(u10), a10 = h10.render(h10.props, h10.state, h10.context), h10.state = h10.__s;
            } while (h10.__d && ++I8 < 25);
          h10.state = h10.__s, null != h10.getChildContext && (i11 = d(d({}, i11), h10.getChildContext())), x11 && !v12 && null != h10.getSnapshotBeforeUpdate && (_7 = h10.getSnapshotBeforeUpdate(p10, w10)), P(n13, y(L10 = null != a10 && a10.type === b && null == a10.key ? a10.props.children : a10) ? L10 : [L10], u10, t17, i11, o13, r10, f11, e22, c10, s11), h10.base = u10.__e, u10.__u &= -161, h10.__h.length && f11.push(h10), g9 && (h10.__E = h10.__ = null);
        } catch (n14) {
          if (u10.__v = null, c10 || null != r10) {
            for (u10.__u |= c10 ? 160 : 128; e22 && 8 === e22.nodeType && e22.nextSibling; )
              e22 = e22.nextSibling;
            r10[r10.indexOf(e22)] = null, u10.__e = e22;
          } else
            u10.__e = t17.__e, u10.__k = t17.__k;
          l.__e(n14, u10, t17);
        }
      else
        null == r10 && u10.__v === t17.__v ? (u10.__k = t17.__k, u10.__e = t17.__e) : u10.__e = z(t17.__e, u10, t17, i11, o13, r10, f11, c10, s11);
    (a10 = l.diffed) && a10(u10);
  }
  function j(n13, u10, t17) {
    u10.__d = void 0;
    for (var i11 = 0; i11 < t17.length; i11++)
      E(t17[i11], t17[++i11], t17[++i11]);
    l.__c && l.__c(u10, n13), n13.some(function(u11) {
      try {
        n13 = u11.__h, u11.__h = [], n13.some(function(n14) {
          n14.call(u11);
        });
      } catch (n14) {
        l.__e(n14, u11.__v);
      }
    });
  }
  function z(u10, t17, i11, o13, r10, f11, e22, c10, s11) {
    var a10, v12, p10, d12, _7, g9, m12, b11 = i11.props, k10 = t17.props, C9 = t17.type;
    if ("svg" === C9 ? r10 = "http://www.w3.org/2000/svg" : "math" === C9 ? r10 = "http://www.w3.org/1998/Math/MathML" : r10 || (r10 = "http://www.w3.org/1999/xhtml"), null != f11) {
      for (a10 = 0; a10 < f11.length; a10++)
        if ((_7 = f11[a10]) && "setAttribute" in _7 == !!C9 && (C9 ? _7.localName === C9 : 3 === _7.nodeType)) {
          u10 = _7, f11[a10] = null;
          break;
        }
    }
    if (null == u10) {
      if (null === C9)
        return document.createTextNode(k10);
      u10 = document.createElementNS(r10, C9, k10.is && k10), c10 && (l.__m && l.__m(t17, f11), c10 = false), f11 = null;
    }
    if (null === C9)
      b11 === k10 || c10 && u10.data === k10 || (u10.data = k10);
    else {
      if (f11 = f11 && n.call(u10.childNodes), b11 = i11.props || h, !c10 && null != f11)
        for (b11 = {}, a10 = 0; a10 < u10.attributes.length; a10++)
          b11[(_7 = u10.attributes[a10]).name] = _7.value;
      for (a10 in b11)
        if (_7 = b11[a10], "children" == a10)
          ;
        else if ("dangerouslySetInnerHTML" == a10)
          p10 = _7;
        else if (!(a10 in k10)) {
          if ("value" == a10 && "defaultValue" in k10 || "checked" == a10 && "defaultChecked" in k10)
            continue;
          A(u10, a10, null, _7, r10);
        }
      for (a10 in k10)
        _7 = k10[a10], "children" == a10 ? d12 = _7 : "dangerouslySetInnerHTML" == a10 ? v12 = _7 : "value" == a10 ? g9 = _7 : "checked" == a10 ? m12 = _7 : c10 && "function" != typeof _7 || b11[a10] === _7 || A(u10, a10, _7, b11[a10], r10);
      if (v12)
        c10 || p10 && (v12.__html === p10.__html || v12.__html === u10.innerHTML) || (u10.innerHTML = v12.__html), t17.__k = [];
      else if (p10 && (u10.innerHTML = ""), P(u10, y(d12) ? d12 : [d12], t17, i11, o13, "foreignObject" === C9 ? "http://www.w3.org/1999/xhtml" : r10, f11, e22, f11 ? f11[0] : i11.__k && x(i11, 0), c10, s11), null != f11)
        for (a10 = f11.length; a10--; )
          w(f11[a10]);
      c10 || (a10 = "value", "progress" === C9 && null == g9 ? u10.removeAttribute("value") : void 0 !== g9 && (g9 !== u10[a10] || "progress" === C9 && !g9 || "option" === C9 && g9 !== b11[a10]) && A(u10, a10, g9, b11[a10], r10), a10 = "checked", void 0 !== m12 && m12 !== u10[a10] && A(u10, a10, m12, b11[a10], r10));
    }
    return u10;
  }
  function E(n13, u10, t17) {
    try {
      if ("function" == typeof n13) {
        var i11 = "function" == typeof n13.__u;
        i11 && n13.__u(), i11 && null == u10 || (n13.__u = n13(u10));
      } else
        n13.current = u10;
    } catch (n14) {
      l.__e(n14, t17);
    }
  }
  function N(n13, u10, t17) {
    var i11, o13;
    if (l.unmount && l.unmount(n13), (i11 = n13.ref) && (i11.current && i11.current !== n13.__e || E(i11, null, u10)), null != (i11 = n13.__c)) {
      if (i11.componentWillUnmount)
        try {
          i11.componentWillUnmount();
        } catch (n14) {
          l.__e(n14, u10);
        }
      i11.base = i11.__P = null;
    }
    if (i11 = n13.__k)
      for (o13 = 0; o13 < i11.length; o13++)
        i11[o13] && N(i11[o13], u10, t17 || "function" != typeof n13.type);
    t17 || w(n13.__e), n13.__c = n13.__ = n13.__e = n13.__d = void 0;
  }
  function V(n13, l11, u10) {
    return this.constructor(n13, u10);
  }
  function q(u10, t17, i11) {
    var o13, r10, f11, e22;
    l.__ && l.__(u10, t17), r10 = (o13 = "function" == typeof i11) ? null : i11 && i11.__k || t17.__k, f11 = [], e22 = [], O(t17, u10 = (!o13 && i11 || t17).__k = _(b, null, [u10]), r10 || h, h, t17.namespaceURI, !o13 && i11 ? [i11] : r10 ? null : t17.firstChild ? n.call(t17.childNodes) : null, f11, !o13 && i11 ? i11 : r10 ? r10.__e : t17.firstChild, o13, e22), j(f11, u10, e22);
  }
  n = v.slice, l = { __e: function(n13, l11, u10, t17) {
    for (var i11, o13, r10; l11 = l11.__; )
      if ((i11 = l11.__c) && !i11.__)
        try {
          if ((o13 = i11.constructor) && null != o13.getDerivedStateFromError && (i11.setState(o13.getDerivedStateFromError(n13)), r10 = i11.__d), null != i11.componentDidCatch && (i11.componentDidCatch(n13, t17 || {}), r10 = i11.__d), r10)
            return i11.__E = i11;
        } catch (l12) {
          n13 = l12;
        }
    throw n13;
  } }, u = 0, t = function(n13) {
    return null != n13 && null == n13.constructor;
  }, k.prototype.setState = function(n13, l11) {
    var u10;
    u10 = null != this.__s && this.__s !== this.state ? this.__s : this.__s = d({}, this.state), "function" == typeof n13 && (n13 = n13(d({}, u10), this.props)), n13 && d(u10, n13), null != n13 && this.__v && (l11 && this._sb.push(l11), S(this));
  }, k.prototype.forceUpdate = function(n13) {
    this.__v && (this.__e = true, n13 && this.__h.push(n13), S(this));
  }, k.prototype.render = b, i = [], r = "function" == typeof Promise ? Promise.prototype.then.bind(Promise.resolve()) : setTimeout, f = function(n13, l11) {
    return n13.__v.__b - l11.__v.__b;
  }, M.__r = 0, e = 0, c = F(false), s = F(true), a = 0;

  // http-url:https://unpkg.com/htm@latest?module
  var n2 = function(t17, s11, r10, e22) {
    var u10;
    s11[0] = 0;
    for (var h10 = 1; h10 < s11.length; h10++) {
      var p10 = s11[h10++], a10 = s11[h10] ? (s11[0] |= p10 ? 1 : 2, r10[s11[h10++]]) : s11[++h10];
      3 === p10 ? e22[0] = a10 : 4 === p10 ? e22[1] = Object.assign(e22[1] || {}, a10) : 5 === p10 ? (e22[1] = e22[1] || {})[s11[++h10]] = a10 : 6 === p10 ? e22[1][s11[++h10]] += a10 + "" : p10 ? (u10 = t17.apply(a10, n2(t17, a10, r10, ["", null])), e22.push(u10), a10[0] ? s11[0] |= 2 : (s11[h10 - 2] = 0, s11[h10] = u10)) : e22.push(a10);
    }
    return e22;
  };
  var t2 = /* @__PURE__ */ new Map();
  function htm_latest_module_default(s11) {
    var r10 = t2.get(this);
    return r10 || (r10 = /* @__PURE__ */ new Map(), t2.set(this, r10)), (r10 = n2(this, r10.get(s11) || (r10.set(s11, r10 = function(n13) {
      for (var t17, s12, r11 = 1, e22 = "", u10 = "", h10 = [0], p10 = function(n14) {
        1 === r11 && (n14 || (e22 = e22.replace(/^\s*\n\s*|\s*\n\s*$/g, ""))) ? h10.push(0, n14, e22) : 3 === r11 && (n14 || e22) ? (h10.push(3, n14, e22), r11 = 2) : 2 === r11 && "..." === e22 && n14 ? h10.push(4, n14, 0) : 2 === r11 && e22 && !n14 ? h10.push(5, 0, true, e22) : r11 >= 5 && ((e22 || !n14 && 5 === r11) && (h10.push(r11, 0, e22, s12), r11 = 6), n14 && (h10.push(r11, n14, 0, s12), r11 = 6)), e22 = "";
      }, a10 = 0; a10 < n13.length; a10++) {
        a10 && (1 === r11 && p10(), p10(a10));
        for (var l11 = 0; l11 < n13[a10].length; l11++)
          t17 = n13[a10][l11], 1 === r11 ? "<" === t17 ? (p10(), h10 = [h10], r11 = 3) : e22 += t17 : 4 === r11 ? "--" === e22 && ">" === t17 ? (r11 = 1, e22 = "") : e22 = t17 + e22[0] : u10 ? t17 === u10 ? u10 = "" : e22 += t17 : '"' === t17 || "'" === t17 ? u10 = t17 : ">" === t17 ? (p10(), r11 = 1) : r11 && ("=" === t17 ? (r11 = 5, s12 = e22, e22 = "") : "/" === t17 && (r11 < 5 || ">" === n13[a10][l11 + 1]) ? (p10(), 3 === r11 && (h10 = h10[0]), r11 = h10, (h10 = h10[0]).push(2, 0, r11), r11 = 0) : " " === t17 || "	" === t17 || "\n" === t17 || "\r" === t17 ? (p10(), r11 = 2) : e22 += t17), 3 === r11 && "!--" === e22 && (r11 = 4, h10 = h10[0]);
      }
      return p10(), h10;
    }(s11)), r10), arguments, [])).length > 1 ? r10 : r10[0];
  }

  // http-url:https://unpkg.com/htm/preact/index.module.js?module
  var m2 = htm_latest_module_default.bind(_);

  // http-url:https://cdn.jsdelivr.net/npm/lodash@4.17.21/debounce/+esm
  var t3 = "undefined" != typeof globalThis ? globalThis : "undefined" != typeof window ? window : "undefined" != typeof global ? global : "undefined" != typeof self ? self : {};
  var n3 = function(t17) {
    var n13 = typeof t17;
    return null != t17 && ("object" == n13 || "function" == n13);
  };
  var e2 = "object" == typeof t3 && t3 && t3.Object === Object && t3;
  var r2 = "object" == typeof self && self && self.Object === Object && self;
  var o2 = e2 || r2 || Function("return this")();
  var i2 = o2;
  var u2 = function() {
    return i2.Date.now();
  };
  var f2 = /\s/;
  var a2 = function(t17) {
    for (var n13 = t17.length; n13-- && f2.test(t17.charAt(n13)); )
      ;
    return n13;
  };
  var c2 = /^\s+/;
  var l2 = function(t17) {
    return t17 ? t17.slice(0, a2(t17) + 1).replace(c2, "") : t17;
  };
  var v2 = o2.Symbol;
  var d2 = v2;
  var s2 = Object.prototype;
  var p2 = s2.hasOwnProperty;
  var b2 = s2.toString;
  var y2 = d2 ? d2.toStringTag : void 0;
  var g2 = function(t17) {
    var n13 = p2.call(t17, y2), e22 = t17[y2];
    try {
      t17[y2] = void 0;
      var r10 = true;
    } catch (t18) {
    }
    var o13 = b2.call(t17);
    return r10 && (n13 ? t17[y2] = e22 : delete t17[y2]), o13;
  };
  var j2 = Object.prototype.toString;
  var m3 = g2;
  var h2 = function(t17) {
    return j2.call(t17);
  };
  var T2 = v2 ? v2.toStringTag : void 0;
  var O2 = function(t17) {
    return null == t17 ? void 0 === t17 ? "[object Undefined]" : "[object Null]" : T2 && T2 in Object(t17) ? m3(t17) : h2(t17);
  };
  var w2 = function(t17) {
    return null != t17 && "object" == typeof t17;
  };
  var x2 = l2;
  var S2 = n3;
  var N2 = function(t17) {
    return "symbol" == typeof t17 || w2(t17) && "[object Symbol]" == O2(t17);
  };
  var $2 = /^[-+]0x[0-9a-f]+$/i;
  var E2 = /^0b[01]+$/i;
  var M2 = /^0o[0-7]+$/i;
  var W = parseInt;
  var A2 = n3;
  var D = u2;
  var F2 = function(t17) {
    if ("number" == typeof t17)
      return t17;
    if (N2(t17))
      return NaN;
    if (S2(t17)) {
      var n13 = "function" == typeof t17.valueOf ? t17.valueOf() : t17;
      t17 = S2(n13) ? n13 + "" : n13;
    }
    if ("string" != typeof t17)
      return 0 === t17 ? t17 : +t17;
    t17 = x2(t17);
    var e22 = E2.test(t17);
    return e22 || M2.test(t17) ? W(t17.slice(2), e22 ? 2 : 8) : $2.test(t17) ? NaN : +t17;
  };
  var I2 = Math.max;
  var P2 = Math.min;
  var U = function(t17, n13, e22) {
    var r10, o13, i11, u10, f11, a10, c10 = 0, l11 = false, v12 = false, d12 = true;
    if ("function" != typeof t17)
      throw new TypeError("Expected a function");
    function s11(n14) {
      var e23 = r10, i12 = o13;
      return r10 = o13 = void 0, c10 = n14, u10 = t17.apply(i12, e23);
    }
    function p10(t18) {
      var e23 = t18 - a10;
      return void 0 === a10 || e23 >= n13 || e23 < 0 || v12 && t18 - c10 >= i11;
    }
    function b11() {
      var t18 = D();
      if (p10(t18))
        return y10(t18);
      f11 = setTimeout(b11, function(t19) {
        var e23 = n13 - (t19 - a10);
        return v12 ? P2(e23, i11 - (t19 - c10)) : e23;
      }(t18));
    }
    function y10(t18) {
      return f11 = void 0, d12 && r10 ? s11(t18) : (r10 = o13 = void 0, u10);
    }
    function g9() {
      var t18 = D(), e23 = p10(t18);
      if (r10 = arguments, o13 = this, a10 = t18, e23) {
        if (void 0 === f11)
          return function(t19) {
            return c10 = t19, f11 = setTimeout(b11, n13), l11 ? s11(t19) : u10;
          }(a10);
        if (v12)
          return clearTimeout(f11), f11 = setTimeout(b11, n13), s11(a10);
      }
      return void 0 === f11 && (f11 = setTimeout(b11, n13)), u10;
    }
    return n13 = F2(n13) || 0, A2(e22) && (l11 = !!e22.leading, i11 = (v12 = "maxWait" in e22) ? I2(F2(e22.maxWait) || 0, n13) : i11, d12 = "trailing" in e22 ? !!e22.trailing : d12), g9.cancel = function() {
      void 0 !== f11 && clearTimeout(f11), c10 = 0, r10 = a10 = o13 = f11 = void 0;
    }, g9.flush = function() {
      return void 0 === f11 ? u10 : y10(D());
    }, g9;
  };

  // http-url:https://cdn.jsdelivr.net/npm/heap@0.2.7/+esm
  var t4;
  var n4 = "undefined" != typeof globalThis ? globalThis : "undefined" != typeof window ? window : "undefined" != typeof global ? global : "undefined" != typeof self ? self : {};
  var e3 = { exports: {} };
  t4 = e3, function() {
    var n13, e22, o13, r10, p10, u10, i11, l11, s11, f11, h10, c10, a10, y10, d12;
    o13 = Math.floor, f11 = Math.min, e22 = function(t17, n14) {
      return t17 < n14 ? -1 : t17 > n14 ? 1 : 0;
    }, s11 = function(t17, n14, r11, p11, u11) {
      var i12;
      if (null == r11 && (r11 = 0), null == u11 && (u11 = e22), r11 < 0)
        throw new Error("lo must be non-negative");
      for (null == p11 && (p11 = t17.length); r11 < p11; )
        u11(n14, t17[i12 = o13((r11 + p11) / 2)]) < 0 ? p11 = i12 : r11 = i12 + 1;
      return [].splice.apply(t17, [r11, r11 - r11].concat(n14)), n14;
    }, u10 = function(t17, n14, o14) {
      return null == o14 && (o14 = e22), t17.push(n14), y10(t17, 0, t17.length - 1, o14);
    }, p10 = function(t17, n14) {
      var o14, r11;
      return null == n14 && (n14 = e22), o14 = t17.pop(), t17.length ? (r11 = t17[0], t17[0] = o14, d12(t17, 0, n14)) : r11 = o14, r11;
    }, l11 = function(t17, n14, o14) {
      var r11;
      return null == o14 && (o14 = e22), r11 = t17[0], t17[0] = n14, d12(t17, 0, o14), r11;
    }, i11 = function(t17, n14, o14) {
      var r11;
      return null == o14 && (o14 = e22), t17.length && o14(t17[0], n14) < 0 && (n14 = (r11 = [t17[0], n14])[0], t17[0] = r11[1], d12(t17, 0, o14)), n14;
    }, r10 = function(t17, n14) {
      var r11, p11, u11, i12, l12, s12;
      for (null == n14 && (n14 = e22), l12 = [], p11 = 0, u11 = (i12 = function() {
        s12 = [];
        for (var n15 = 0, e23 = o13(t17.length / 2); 0 <= e23 ? n15 < e23 : n15 > e23; 0 <= e23 ? n15++ : n15--)
          s12.push(n15);
        return s12;
      }.apply(this).reverse()).length; p11 < u11; p11++)
        r11 = i12[p11], l12.push(d12(t17, r11, n14));
      return l12;
    }, a10 = function(t17, n14, o14) {
      var r11;
      if (null == o14 && (o14 = e22), -1 !== (r11 = t17.indexOf(n14)))
        return y10(t17, 0, r11, o14), d12(t17, r11, o14);
    }, h10 = function(t17, n14, o14) {
      var p11, u11, l12, s12, f12;
      if (null == o14 && (o14 = e22), !(u11 = t17.slice(0, n14)).length)
        return u11;
      for (r10(u11, o14), l12 = 0, s12 = (f12 = t17.slice(n14)).length; l12 < s12; l12++)
        p11 = f12[l12], i11(u11, p11, o14);
      return u11.sort(o14).reverse();
    }, c10 = function(t17, n14, o14) {
      var u11, i12, l12, h11, c11, a11, y11, d13, g9;
      if (null == o14 && (o14 = e22), 10 * n14 <= t17.length) {
        if (!(l12 = t17.slice(0, n14).sort(o14)).length)
          return l12;
        for (i12 = l12[l12.length - 1], h11 = 0, a11 = (y11 = t17.slice(n14)).length; h11 < a11; h11++)
          o14(u11 = y11[h11], i12) < 0 && (s11(l12, u11, 0, null, o14), l12.pop(), i12 = l12[l12.length - 1]);
        return l12;
      }
      for (r10(t17, o14), g9 = [], c11 = 0, d13 = f11(n14, t17.length); 0 <= d13 ? c11 < d13 : c11 > d13; 0 <= d13 ? ++c11 : --c11)
        g9.push(p10(t17, o14));
      return g9;
    }, y10 = function(t17, n14, o14, r11) {
      var p11, u11, i12;
      for (null == r11 && (r11 = e22), p11 = t17[o14]; o14 > n14 && r11(p11, u11 = t17[i12 = o14 - 1 >> 1]) < 0; )
        t17[o14] = u11, o14 = i12;
      return t17[o14] = p11;
    }, d12 = function(t17, n14, o14) {
      var r11, p11, u11, i12, l12;
      for (null == o14 && (o14 = e22), p11 = t17.length, l12 = n14, u11 = t17[n14], r11 = 2 * n14 + 1; r11 < p11; )
        (i12 = r11 + 1) < p11 && !(o14(t17[r11], t17[i12]) < 0) && (r11 = i12), t17[n14] = t17[r11], r11 = 2 * (n14 = r11) + 1;
      return t17[n14] = u11, y10(t17, l12, n14, o14);
    }, n13 = function() {
      function t17(t18) {
        this.cmp = null != t18 ? t18 : e22, this.nodes = [];
      }
      return t17.push = u10, t17.pop = p10, t17.replace = l11, t17.pushpop = i11, t17.heapify = r10, t17.updateItem = a10, t17.nlargest = h10, t17.nsmallest = c10, t17.prototype.push = function(t18) {
        return u10(this.nodes, t18, this.cmp);
      }, t17.prototype.pop = function() {
        return p10(this.nodes, this.cmp);
      }, t17.prototype.peek = function() {
        return this.nodes[0];
      }, t17.prototype.contains = function(t18) {
        return -1 !== this.nodes.indexOf(t18);
      }, t17.prototype.replace = function(t18) {
        return l11(this.nodes, t18, this.cmp);
      }, t17.prototype.pushpop = function(t18) {
        return i11(this.nodes, t18, this.cmp);
      }, t17.prototype.heapify = function() {
        return r10(this.nodes, this.cmp);
      }, t17.prototype.updateItem = function(t18) {
        return a10(this.nodes, t18, this.cmp);
      }, t17.prototype.clear = function() {
        return this.nodes = [];
      }, t17.prototype.empty = function() {
        return 0 === this.nodes.length;
      }, t17.prototype.size = function() {
        return this.nodes.length;
      }, t17.prototype.clone = function() {
        var n14;
        return (n14 = new t17()).nodes = this.nodes.slice(0), n14;
      }, t17.prototype.toArray = function() {
        return this.nodes.slice(0);
      }, t17.prototype.insert = t17.prototype.push, t17.prototype.top = t17.prototype.peek, t17.prototype.front = t17.prototype.peek, t17.prototype.has = t17.prototype.contains, t17.prototype.copy = t17.prototype.clone, t17;
    }(), t4.exports = n13;
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
  var f3 = function(t17) {
    var r10 = c3.call(t17, l3), n13 = t17[l3];
    try {
      t17[l3] = void 0;
      var e22 = true;
    } catch (t18) {
    }
    var o13 = s3.call(t17);
    return e22 && (r10 ? t17[l3] = n13 : delete t17[l3]), o13;
  };
  var v3 = Object.prototype.toString;
  var p3 = f3;
  var h3 = function(t17) {
    return v3.call(t17);
  };
  var _2 = a3 ? a3.toStringTag : void 0;
  var y3 = function(t17) {
    return null == t17 ? void 0 === t17 ? "[object Undefined]" : "[object Null]" : _2 && _2 in Object(t17) ? p3(t17) : h3(t17);
  };
  var d4 = y3;
  var b3 = function(t17) {
    return null != t17 && "object" == typeof t17;
  };
  var g3 = function(t17) {
    return "symbol" == typeof t17 || b3(t17) && "[object Symbol]" == d4(t17);
  };
  var j3 = r3;
  var O3 = g3;
  var w3 = /\.|\[(?:[^[\]]*|(["'])(?:(?!\1)[^\\]|\\.)*?\1)\]/;
  var z2 = /^\w*$/;
  var m4 = function(t17, r10) {
    if (j3(t17))
      return false;
    var n13 = typeof t17;
    return !("number" != n13 && "symbol" != n13 && "boolean" != n13 && null != t17 && !O3(t17)) || (z2.test(t17) || !w3.test(t17) || null != r10 && t17 in Object(r10));
  };
  var S3 = function(t17) {
    var r10 = typeof t17;
    return null != t17 && ("object" == r10 || "function" == r10);
  };
  var $3 = y3;
  var P3 = S3;
  var A3;
  var F3 = function(t17) {
    if (!P3(t17))
      return false;
    var r10 = $3(t17);
    return "[object Function]" == r10 || "[object GeneratorFunction]" == r10 || "[object AsyncFunction]" == r10 || "[object Proxy]" == r10;
  };
  var T3 = o4["__core-js_shared__"];
  var x3 = (A3 = /[^.]+$/.exec(T3 && T3.keys && T3.keys.IE_PROTO || "")) ? "Symbol(src)_1." + A3 : "";
  var C2 = function(t17) {
    return !!x3 && x3 in t17;
  };
  var E3 = Function.prototype.toString;
  var I3 = F3;
  var k2 = C2;
  var R = S3;
  var G = function(t17) {
    if (null != t17) {
      try {
        return E3.call(t17);
      } catch (t18) {
      }
      try {
        return t17 + "";
      } catch (t18) {
      }
    }
    return "";
  };
  var M3 = /^\[object .+?Constructor\]$/;
  var N3 = Function.prototype;
  var U2 = Object.prototype;
  var q2 = N3.toString;
  var B = U2.hasOwnProperty;
  var D2 = RegExp("^" + q2.call(B).replace(/[\\^$.*+?()[\]{}|]/g, "\\$&").replace(/hasOwnProperty|(function).*?(?=\\\()| for .+?(?=\\\])/g, "$1.*?") + "$");
  var H = function(t17) {
    return !(!R(t17) || k2(t17)) && (I3(t17) ? D2 : M3).test(G(t17));
  };
  var J = function(t17, r10) {
    return null == t17 ? void 0 : t17[r10];
  };
  var K = function(t17, r10) {
    var n13 = J(t17, r10);
    return H(n13) ? n13 : void 0;
  };
  var L2 = K(Object, "create");
  var Q = L2;
  var V2 = function() {
    this.__data__ = Q ? Q(null) : {}, this.size = 0;
  };
  var W2 = function(t17) {
    var r10 = this.has(t17) && delete this.__data__[t17];
    return this.size -= r10 ? 1 : 0, r10;
  };
  var X = L2;
  var Y = Object.prototype.hasOwnProperty;
  var Z = function(t17) {
    var r10 = this.__data__;
    if (X) {
      var n13 = r10[t17];
      return "__lodash_hash_undefined__" === n13 ? void 0 : n13;
    }
    return Y.call(r10, t17) ? r10[t17] : void 0;
  };
  var tt = L2;
  var rt = Object.prototype.hasOwnProperty;
  var nt = L2;
  var et = V2;
  var ot = W2;
  var at = Z;
  var it = function(t17) {
    var r10 = this.__data__;
    return tt ? void 0 !== r10[t17] : rt.call(r10, t17);
  };
  var ut = function(t17, r10) {
    var n13 = this.__data__;
    return this.size += this.has(t17) ? 0 : 1, n13[t17] = nt && void 0 === r10 ? "__lodash_hash_undefined__" : r10, this;
  };
  function ct(t17) {
    var r10 = -1, n13 = null == t17 ? 0 : t17.length;
    for (this.clear(); ++r10 < n13; ) {
      var e22 = t17[r10];
      this.set(e22[0], e22[1]);
    }
  }
  ct.prototype.clear = et, ct.prototype.delete = ot, ct.prototype.get = at, ct.prototype.has = it, ct.prototype.set = ut;
  var st = ct;
  var lt = function() {
    this.__data__ = [], this.size = 0;
  };
  var ft = function(t17, r10) {
    return t17 === r10 || t17 != t17 && r10 != r10;
  };
  var vt = function(t17, r10) {
    for (var n13 = t17.length; n13--; )
      if (ft(t17[n13][0], r10))
        return n13;
    return -1;
  };
  var pt = vt;
  var ht = Array.prototype.splice;
  var _t = vt;
  var yt = vt;
  var dt = vt;
  var bt = lt;
  var gt = function(t17) {
    var r10 = this.__data__, n13 = pt(r10, t17);
    return !(n13 < 0) && (n13 == r10.length - 1 ? r10.pop() : ht.call(r10, n13, 1), --this.size, true);
  };
  var jt = function(t17) {
    var r10 = this.__data__, n13 = _t(r10, t17);
    return n13 < 0 ? void 0 : r10[n13][1];
  };
  var Ot = function(t17) {
    return yt(this.__data__, t17) > -1;
  };
  var wt = function(t17, r10) {
    var n13 = this.__data__, e22 = dt(n13, t17);
    return e22 < 0 ? (++this.size, n13.push([t17, r10])) : n13[e22][1] = r10, this;
  };
  function zt(t17) {
    var r10 = -1, n13 = null == t17 ? 0 : t17.length;
    for (this.clear(); ++r10 < n13; ) {
      var e22 = t17[r10];
      this.set(e22[0], e22[1]);
    }
  }
  zt.prototype.clear = bt, zt.prototype.delete = gt, zt.prototype.get = jt, zt.prototype.has = Ot, zt.prototype.set = wt;
  var mt = zt;
  var St = K(o4, "Map");
  var $t = st;
  var Pt = mt;
  var At = St;
  var Ft = function(t17) {
    var r10 = typeof t17;
    return "string" == r10 || "number" == r10 || "symbol" == r10 || "boolean" == r10 ? "__proto__" !== t17 : null === t17;
  };
  var Tt = function(t17, r10) {
    var n13 = t17.__data__;
    return Ft(r10) ? n13["string" == typeof r10 ? "string" : "hash"] : n13.map;
  };
  var xt = Tt;
  var Ct = Tt;
  var Et = Tt;
  var It = Tt;
  var kt = function() {
    this.size = 0, this.__data__ = { hash: new $t(), map: new (At || Pt)(), string: new $t() };
  };
  var Rt = function(t17) {
    var r10 = xt(this, t17).delete(t17);
    return this.size -= r10 ? 1 : 0, r10;
  };
  var Gt = function(t17) {
    return Ct(this, t17).get(t17);
  };
  var Mt = function(t17) {
    return Et(this, t17).has(t17);
  };
  var Nt = function(t17, r10) {
    var n13 = It(this, t17), e22 = n13.size;
    return n13.set(t17, r10), this.size += n13.size == e22 ? 0 : 1, this;
  };
  function Ut(t17) {
    var r10 = -1, n13 = null == t17 ? 0 : t17.length;
    for (this.clear(); ++r10 < n13; ) {
      var e22 = t17[r10];
      this.set(e22[0], e22[1]);
    }
  }
  Ut.prototype.clear = kt, Ut.prototype.delete = Rt, Ut.prototype.get = Gt, Ut.prototype.has = Mt, Ut.prototype.set = Nt;
  var qt = Ut;
  function Bt(t17, r10) {
    if ("function" != typeof t17 || null != r10 && "function" != typeof r10)
      throw new TypeError("Expected a function");
    var n13 = function() {
      var e22 = arguments, o13 = r10 ? r10.apply(this, e22) : e22[0], a10 = n13.cache;
      if (a10.has(o13))
        return a10.get(o13);
      var i11 = t17.apply(this, e22);
      return n13.cache = a10.set(o13, i11) || a10, i11;
    };
    return n13.cache = new (Bt.Cache || qt)(), n13;
  }
  Bt.Cache = qt;
  var Dt = Bt;
  var Ht = /[^.[\]]+|\[(?:(-?\d+(?:\.\d+)?)|(["'])((?:(?!\2)[^\\]|\\.)*?)\2)\]|(?=(?:\.|\[\])(?:\.|\[\]|$))/g;
  var Jt = /\\(\\)?/g;
  var Kt = function(t17) {
    var r10 = Dt(t17, function(t18) {
      return 500 === n13.size && n13.clear(), t18;
    }), n13 = r10.cache;
    return r10;
  }(function(t17) {
    var r10 = [];
    return 46 === t17.charCodeAt(0) && r10.push(""), t17.replace(Ht, function(t18, n13, e22, o13) {
      r10.push(e22 ? o13.replace(Jt, "$1") : n13 || t18);
    }), r10;
  });
  var Lt = function(t17, r10) {
    for (var n13 = -1, e22 = null == t17 ? 0 : t17.length, o13 = Array(e22); ++n13 < e22; )
      o13[n13] = r10(t17[n13], n13, t17);
    return o13;
  };
  var Qt = r3;
  var Vt = g3;
  var Wt = a3 ? a3.prototype : void 0;
  var Xt = Wt ? Wt.toString : void 0;
  var Yt = function t6(r10) {
    if ("string" == typeof r10)
      return r10;
    if (Qt(r10))
      return Lt(r10, t6) + "";
    if (Vt(r10))
      return Xt ? Xt.call(r10) : "";
    var n13 = r10 + "";
    return "0" == n13 && 1 / r10 == -Infinity ? "-0" : n13;
  };
  var Zt = Yt;
  var tr = r3;
  var rr = m4;
  var nr = Kt;
  var er = function(t17) {
    return null == t17 ? "" : Zt(t17);
  };
  var or = g3;
  var ar = function(t17, r10) {
    return tr(t17) ? t17 : rr(t17, r10) ? [t17] : nr(er(t17));
  };
  var ir = function(t17) {
    if ("string" == typeof t17 || or(t17))
      return t17;
    var r10 = t17 + "";
    return "0" == r10 && 1 / t17 == -Infinity ? "-0" : r10;
  };
  var ur = function(t17, r10) {
    for (var n13 = 0, e22 = (r10 = ar(r10, t17)).length; null != t17 && n13 < e22; )
      t17 = t17[ir(r10[n13++])];
    return n13 && n13 == e22 ? t17 : void 0;
  };
  var cr = function(t17, r10, n13) {
    var e22 = null == t17 ? void 0 : ur(t17, r10);
    return void 0 === e22 ? n13 : e22;
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
  var f4 = function(t17) {
    var r10 = u4.call(t17, l4), n13 = t17[l4];
    try {
      t17[l4] = void 0;
      var e22 = true;
    } catch (t18) {
    }
    var o13 = c4.call(t17);
    return e22 && (r10 ? t17[l4] = n13 : delete t17[l4]), o13;
  };
  var s4 = Object.prototype.toString;
  var v4 = f4;
  var p4 = function(t17) {
    return s4.call(t17);
  };
  var h4 = o5 ? o5.toStringTag : void 0;
  var _3 = function(t17) {
    return null == t17 ? void 0 === t17 ? "[object Undefined]" : "[object Null]" : h4 && h4 in Object(t17) ? v4(t17) : p4(t17);
  };
  var y4 = function(t17) {
    var r10 = typeof t17;
    return null != t17 && ("object" == r10 || "function" == r10);
  };
  var d5 = _3;
  var b4 = y4;
  var g4;
  var j4 = function(t17) {
    if (!b4(t17))
      return false;
    var r10 = d5(t17);
    return "[object Function]" == r10 || "[object GeneratorFunction]" == r10 || "[object AsyncFunction]" == r10 || "[object Proxy]" == r10;
  };
  var O4 = e5["__core-js_shared__"];
  var w4 = (g4 = /[^.]+$/.exec(O4 && O4.keys && O4.keys.IE_PROTO || "")) ? "Symbol(src)_1." + g4 : "";
  var m5 = function(t17) {
    return !!w4 && w4 in t17;
  };
  var z3 = Function.prototype.toString;
  var S4 = j4;
  var $4 = m5;
  var P4 = y4;
  var A4 = function(t17) {
    if (null != t17) {
      try {
        return z3.call(t17);
      } catch (t18) {
      }
      try {
        return t17 + "";
      } catch (t18) {
      }
    }
    return "";
  };
  var F4 = /^\[object .+?Constructor\]$/;
  var T4 = Function.prototype;
  var x4 = Object.prototype;
  var C3 = T4.toString;
  var E4 = x4.hasOwnProperty;
  var I4 = RegExp("^" + C3.call(E4).replace(/[\\^$.*+?()[\]{}|]/g, "\\$&").replace(/hasOwnProperty|(function).*?(?=\\\()| for .+?(?=\\\])/g, "$1.*?") + "$");
  var k3 = function(t17) {
    return !(!P4(t17) || $4(t17)) && (S4(t17) ? I4 : F4).test(A4(t17));
  };
  var R2 = function(t17, r10) {
    return null == t17 ? void 0 : t17[r10];
  };
  var G2 = function(t17, r10) {
    var n13 = R2(t17, r10);
    return k3(n13) ? n13 : void 0;
  };
  var M4 = G2;
  var N4 = function() {
    try {
      var t17 = M4(Object, "defineProperty");
      return t17({}, "", {}), t17;
    } catch (t18) {
    }
  }();
  var U3 = function(t17, r10) {
    return t17 === r10 || t17 != t17 && r10 != r10;
  };
  var q3 = function(t17, r10, n13) {
    "__proto__" == r10 && N4 ? N4(t17, r10, { configurable: true, enumerable: true, value: n13, writable: true }) : t17[r10] = n13;
  };
  var B2 = U3;
  var D3 = Object.prototype.hasOwnProperty;
  var H2 = function(t17, r10, n13) {
    var e22 = t17[r10];
    D3.call(t17, r10) && B2(e22, n13) && (void 0 !== n13 || r10 in t17) || q3(t17, r10, n13);
  };
  var J2 = Array.isArray;
  var K2 = _3;
  var L3 = function(t17) {
    return null != t17 && "object" == typeof t17;
  };
  var Q2 = function(t17) {
    return "symbol" == typeof t17 || L3(t17) && "[object Symbol]" == K2(t17);
  };
  var V3 = J2;
  var W3 = Q2;
  var X2 = /\.|\[(?:[^[\]]*|(["'])(?:(?!\1)[^\\]|\\.)*?\1)\]/;
  var Y2 = /^\w*$/;
  var Z2 = function(t17, r10) {
    if (V3(t17))
      return false;
    var n13 = typeof t17;
    return !("number" != n13 && "symbol" != n13 && "boolean" != n13 && null != t17 && !W3(t17)) || (Y2.test(t17) || !X2.test(t17) || null != r10 && t17 in Object(r10));
  };
  var tt2 = G2(Object, "create");
  var rt2 = tt2;
  var nt2 = function() {
    this.__data__ = rt2 ? rt2(null) : {}, this.size = 0;
  };
  var et2 = function(t17) {
    var r10 = this.has(t17) && delete this.__data__[t17];
    return this.size -= r10 ? 1 : 0, r10;
  };
  var ot2 = tt2;
  var at2 = Object.prototype.hasOwnProperty;
  var it2 = function(t17) {
    var r10 = this.__data__;
    if (ot2) {
      var n13 = r10[t17];
      return "__lodash_hash_undefined__" === n13 ? void 0 : n13;
    }
    return at2.call(r10, t17) ? r10[t17] : void 0;
  };
  var ut2 = tt2;
  var ct2 = Object.prototype.hasOwnProperty;
  var lt2 = tt2;
  var ft2 = nt2;
  var st2 = et2;
  var vt2 = it2;
  var pt2 = function(t17) {
    var r10 = this.__data__;
    return ut2 ? void 0 !== r10[t17] : ct2.call(r10, t17);
  };
  var ht2 = function(t17, r10) {
    var n13 = this.__data__;
    return this.size += this.has(t17) ? 0 : 1, n13[t17] = lt2 && void 0 === r10 ? "__lodash_hash_undefined__" : r10, this;
  };
  function _t2(t17) {
    var r10 = -1, n13 = null == t17 ? 0 : t17.length;
    for (this.clear(); ++r10 < n13; ) {
      var e22 = t17[r10];
      this.set(e22[0], e22[1]);
    }
  }
  _t2.prototype.clear = ft2, _t2.prototype.delete = st2, _t2.prototype.get = vt2, _t2.prototype.has = pt2, _t2.prototype.set = ht2;
  var yt2 = _t2;
  var dt2 = function() {
    this.__data__ = [], this.size = 0;
  };
  var bt2 = U3;
  var gt2 = function(t17, r10) {
    for (var n13 = t17.length; n13--; )
      if (bt2(t17[n13][0], r10))
        return n13;
    return -1;
  };
  var jt2 = gt2;
  var Ot2 = Array.prototype.splice;
  var wt2 = gt2;
  var mt2 = gt2;
  var zt2 = gt2;
  var St2 = dt2;
  var $t2 = function(t17) {
    var r10 = this.__data__, n13 = jt2(r10, t17);
    return !(n13 < 0) && (n13 == r10.length - 1 ? r10.pop() : Ot2.call(r10, n13, 1), --this.size, true);
  };
  var Pt2 = function(t17) {
    var r10 = this.__data__, n13 = wt2(r10, t17);
    return n13 < 0 ? void 0 : r10[n13][1];
  };
  var At2 = function(t17) {
    return mt2(this.__data__, t17) > -1;
  };
  var Ft2 = function(t17, r10) {
    var n13 = this.__data__, e22 = zt2(n13, t17);
    return e22 < 0 ? (++this.size, n13.push([t17, r10])) : n13[e22][1] = r10, this;
  };
  function Tt2(t17) {
    var r10 = -1, n13 = null == t17 ? 0 : t17.length;
    for (this.clear(); ++r10 < n13; ) {
      var e22 = t17[r10];
      this.set(e22[0], e22[1]);
    }
  }
  Tt2.prototype.clear = St2, Tt2.prototype.delete = $t2, Tt2.prototype.get = Pt2, Tt2.prototype.has = At2, Tt2.prototype.set = Ft2;
  var xt2 = Tt2;
  var Ct2 = G2(e5, "Map");
  var Et2 = yt2;
  var It2 = xt2;
  var kt2 = Ct2;
  var Rt2 = function(t17) {
    var r10 = typeof t17;
    return "string" == r10 || "number" == r10 || "symbol" == r10 || "boolean" == r10 ? "__proto__" !== t17 : null === t17;
  };
  var Gt2 = function(t17, r10) {
    var n13 = t17.__data__;
    return Rt2(r10) ? n13["string" == typeof r10 ? "string" : "hash"] : n13.map;
  };
  var Mt2 = Gt2;
  var Nt2 = Gt2;
  var Ut2 = Gt2;
  var qt2 = Gt2;
  var Bt2 = function() {
    this.size = 0, this.__data__ = { hash: new Et2(), map: new (kt2 || It2)(), string: new Et2() };
  };
  var Dt2 = function(t17) {
    var r10 = Mt2(this, t17).delete(t17);
    return this.size -= r10 ? 1 : 0, r10;
  };
  var Ht2 = function(t17) {
    return Nt2(this, t17).get(t17);
  };
  var Jt2 = function(t17) {
    return Ut2(this, t17).has(t17);
  };
  var Kt2 = function(t17, r10) {
    var n13 = qt2(this, t17), e22 = n13.size;
    return n13.set(t17, r10), this.size += n13.size == e22 ? 0 : 1, this;
  };
  function Lt2(t17) {
    var r10 = -1, n13 = null == t17 ? 0 : t17.length;
    for (this.clear(); ++r10 < n13; ) {
      var e22 = t17[r10];
      this.set(e22[0], e22[1]);
    }
  }
  Lt2.prototype.clear = Bt2, Lt2.prototype.delete = Dt2, Lt2.prototype.get = Ht2, Lt2.prototype.has = Jt2, Lt2.prototype.set = Kt2;
  var Qt2 = Lt2;
  function Vt2(t17, r10) {
    if ("function" != typeof t17 || null != r10 && "function" != typeof r10)
      throw new TypeError("Expected a function");
    var n13 = function() {
      var e22 = arguments, o13 = r10 ? r10.apply(this, e22) : e22[0], a10 = n13.cache;
      if (a10.has(o13))
        return a10.get(o13);
      var i11 = t17.apply(this, e22);
      return n13.cache = a10.set(o13, i11) || a10, i11;
    };
    return n13.cache = new (Vt2.Cache || Qt2)(), n13;
  }
  Vt2.Cache = Qt2;
  var Wt2 = Vt2;
  var Xt2 = /[^.[\]]+|\[(?:(-?\d+(?:\.\d+)?)|(["'])((?:(?!\2)[^\\]|\\.)*?)\2)\]|(?=(?:\.|\[\])(?:\.|\[\]|$))/g;
  var Yt2 = /\\(\\)?/g;
  var Zt2 = function(t17) {
    var r10 = Wt2(t17, function(t18) {
      return 500 === n13.size && n13.clear(), t18;
    }), n13 = r10.cache;
    return r10;
  }(function(t17) {
    var r10 = [];
    return 46 === t17.charCodeAt(0) && r10.push(""), t17.replace(Xt2, function(t18, n13, e22, o13) {
      r10.push(e22 ? o13.replace(Yt2, "$1") : n13 || t18);
    }), r10;
  });
  var tr2 = function(t17, r10) {
    for (var n13 = -1, e22 = null == t17 ? 0 : t17.length, o13 = Array(e22); ++n13 < e22; )
      o13[n13] = r10(t17[n13], n13, t17);
    return o13;
  };
  var rr2 = J2;
  var nr2 = Q2;
  var er2 = o5 ? o5.prototype : void 0;
  var or2 = er2 ? er2.toString : void 0;
  var ar2 = function t8(r10) {
    if ("string" == typeof r10)
      return r10;
    if (rr2(r10))
      return tr2(r10, t8) + "";
    if (nr2(r10))
      return or2 ? or2.call(r10) : "";
    var n13 = r10 + "";
    return "0" == n13 && 1 / r10 == -Infinity ? "-0" : n13;
  };
  var ir2 = ar2;
  var ur2 = J2;
  var cr2 = Z2;
  var lr = Zt2;
  var fr = function(t17) {
    return null == t17 ? "" : ir2(t17);
  };
  var sr = /^(?:0|[1-9]\d*)$/;
  var vr = Q2;
  var pr = H2;
  var hr = function(t17, r10) {
    return ur2(t17) ? t17 : cr2(t17, r10) ? [t17] : lr(fr(t17));
  };
  var _r = function(t17, r10) {
    var n13 = typeof t17;
    return !!(r10 = null == r10 ? 9007199254740991 : r10) && ("number" == n13 || "symbol" != n13 && sr.test(t17)) && t17 > -1 && t17 % 1 == 0 && t17 < r10;
  };
  var yr = y4;
  var dr = function(t17) {
    if ("string" == typeof t17 || vr(t17))
      return t17;
    var r10 = t17 + "";
    return "0" == r10 && 1 / t17 == -Infinity ? "-0" : r10;
  };
  var br = function(t17, r10, n13, e22) {
    if (!yr(t17))
      return t17;
    for (var o13 = -1, a10 = (r10 = hr(r10, t17)).length, i11 = a10 - 1, u10 = t17; null != u10 && ++o13 < a10; ) {
      var c10 = dr(r10[o13]), l11 = n13;
      if ("__proto__" === c10 || "constructor" === c10 || "prototype" === c10)
        return t17;
      if (o13 != i11) {
        var f11 = u10[c10];
        void 0 === (l11 = e22 ? e22(f11, c10, u10) : void 0) && (l11 = yr(f11) ? f11 : _r(r10[o13 + 1]) ? [] : {});
      }
      pr(u10, c10, l11), u10 = u10[c10];
    }
    return t17;
  };
  var gr = function(t17, r10, n13) {
    return null == t17 ? t17 : br(t17, r10, n13);
  };

  // http-url:https://cdn.jsdelivr.net/npm/lodash@4.17.21/toPath/+esm
  var t9 = "undefined" != typeof globalThis ? globalThis : "undefined" != typeof window ? window : "undefined" != typeof global ? global : "undefined" != typeof self ? self : {};
  var r5 = function(t17, r10) {
    for (var e22 = -1, n13 = null == t17 ? 0 : t17.length, o13 = Array(n13); ++e22 < n13; )
      o13[e22] = r10(t17[e22], e22, t17);
    return o13;
  };
  var e6 = function(t17, r10) {
    var e22 = -1, n13 = t17.length;
    for (r10 || (r10 = Array(n13)); ++e22 < n13; )
      r10[e22] = t17[e22];
    return r10;
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
  var v5 = function(t17) {
    var r10 = f5.call(t17, p5), e22 = t17[p5];
    try {
      t17[p5] = void 0;
      var n13 = true;
    } catch (t18) {
    }
    var o13 = l5.call(t17);
    return n13 && (r10 ? t17[p5] = e22 : delete t17[p5]), o13;
  };
  var h5 = Object.prototype.toString;
  var _4 = v5;
  var y5 = function(t17) {
    return h5.call(t17);
  };
  var d6 = u5 ? u5.toStringTag : void 0;
  var g5 = function(t17) {
    return null == t17 ? void 0 === t17 ? "[object Undefined]" : "[object Null]" : d6 && d6 in Object(t17) ? _4(t17) : y5(t17);
  };
  var b5 = g5;
  var j5 = function(t17) {
    return null != t17 && "object" == typeof t17;
  };
  var O5 = function(t17) {
    return "symbol" == typeof t17 || j5(t17) && "[object Symbol]" == b5(t17);
  };
  var w5 = function(t17) {
    var r10 = typeof t17;
    return null != t17 && ("object" == r10 || "function" == r10);
  };
  var z4 = g5;
  var S5 = w5;
  var m6;
  var $5 = function(t17) {
    if (!S5(t17))
      return false;
    var r10 = z4(t17);
    return "[object Function]" == r10 || "[object GeneratorFunction]" == r10 || "[object AsyncFunction]" == r10 || "[object Proxy]" == r10;
  };
  var A5 = i5["__core-js_shared__"];
  var P5 = (m6 = /[^.]+$/.exec(A5 && A5.keys && A5.keys.IE_PROTO || "")) ? "Symbol(src)_1." + m6 : "";
  var F5 = function(t17) {
    return !!P5 && P5 in t17;
  };
  var T5 = Function.prototype.toString;
  var x5 = $5;
  var C4 = F5;
  var E5 = w5;
  var I5 = function(t17) {
    if (null != t17) {
      try {
        return T5.call(t17);
      } catch (t18) {
      }
      try {
        return t17 + "";
      } catch (t18) {
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
  var q4 = function(t17) {
    return !(!E5(t17) || C4(t17)) && (x5(t17) ? U4 : k4).test(I5(t17));
  };
  var B3 = function(t17, r10) {
    return null == t17 ? void 0 : t17[r10];
  };
  var D4 = function(t17, r10) {
    var e22 = B3(t17, r10);
    return q4(e22) ? e22 : void 0;
  };
  var H3 = D4(Object, "create");
  var J3 = H3;
  var K3 = function() {
    this.__data__ = J3 ? J3(null) : {}, this.size = 0;
  };
  var L4 = function(t17) {
    var r10 = this.has(t17) && delete this.__data__[t17];
    return this.size -= r10 ? 1 : 0, r10;
  };
  var Q3 = H3;
  var V4 = Object.prototype.hasOwnProperty;
  var W4 = function(t17) {
    var r10 = this.__data__;
    if (Q3) {
      var e22 = r10[t17];
      return "__lodash_hash_undefined__" === e22 ? void 0 : e22;
    }
    return V4.call(r10, t17) ? r10[t17] : void 0;
  };
  var X3 = H3;
  var Y3 = Object.prototype.hasOwnProperty;
  var Z3 = H3;
  var tt3 = K3;
  var rt3 = L4;
  var et3 = W4;
  var nt3 = function(t17) {
    var r10 = this.__data__;
    return X3 ? void 0 !== r10[t17] : Y3.call(r10, t17);
  };
  var ot3 = function(t17, r10) {
    var e22 = this.__data__;
    return this.size += this.has(t17) ? 0 : 1, e22[t17] = Z3 && void 0 === r10 ? "__lodash_hash_undefined__" : r10, this;
  };
  function at3(t17) {
    var r10 = -1, e22 = null == t17 ? 0 : t17.length;
    for (this.clear(); ++r10 < e22; ) {
      var n13 = t17[r10];
      this.set(n13[0], n13[1]);
    }
  }
  at3.prototype.clear = tt3, at3.prototype.delete = rt3, at3.prototype.get = et3, at3.prototype.has = nt3, at3.prototype.set = ot3;
  var it3 = at3;
  var ut3 = function() {
    this.__data__ = [], this.size = 0;
  };
  var ct3 = function(t17, r10) {
    return t17 === r10 || t17 != t17 && r10 != r10;
  };
  var st3 = function(t17, r10) {
    for (var e22 = t17.length; e22--; )
      if (ct3(t17[e22][0], r10))
        return e22;
    return -1;
  };
  var ft3 = st3;
  var lt3 = Array.prototype.splice;
  var pt3 = st3;
  var vt3 = st3;
  var ht3 = st3;
  var _t3 = ut3;
  var yt3 = function(t17) {
    var r10 = this.__data__, e22 = ft3(r10, t17);
    return !(e22 < 0) && (e22 == r10.length - 1 ? r10.pop() : lt3.call(r10, e22, 1), --this.size, true);
  };
  var dt3 = function(t17) {
    var r10 = this.__data__, e22 = pt3(r10, t17);
    return e22 < 0 ? void 0 : r10[e22][1];
  };
  var gt3 = function(t17) {
    return vt3(this.__data__, t17) > -1;
  };
  var bt3 = function(t17, r10) {
    var e22 = this.__data__, n13 = ht3(e22, t17);
    return n13 < 0 ? (++this.size, e22.push([t17, r10])) : e22[n13][1] = r10, this;
  };
  function jt3(t17) {
    var r10 = -1, e22 = null == t17 ? 0 : t17.length;
    for (this.clear(); ++r10 < e22; ) {
      var n13 = t17[r10];
      this.set(n13[0], n13[1]);
    }
  }
  jt3.prototype.clear = _t3, jt3.prototype.delete = yt3, jt3.prototype.get = dt3, jt3.prototype.has = gt3, jt3.prototype.set = bt3;
  var Ot3 = jt3;
  var wt3 = D4(i5, "Map");
  var zt3 = it3;
  var St3 = Ot3;
  var mt3 = wt3;
  var $t3 = function(t17) {
    var r10 = typeof t17;
    return "string" == r10 || "number" == r10 || "symbol" == r10 || "boolean" == r10 ? "__proto__" !== t17 : null === t17;
  };
  var At3 = function(t17, r10) {
    var e22 = t17.__data__;
    return $t3(r10) ? e22["string" == typeof r10 ? "string" : "hash"] : e22.map;
  };
  var Pt3 = At3;
  var Ft3 = At3;
  var Tt3 = At3;
  var xt3 = At3;
  var Ct3 = function() {
    this.size = 0, this.__data__ = { hash: new zt3(), map: new (mt3 || St3)(), string: new zt3() };
  };
  var Et3 = function(t17) {
    var r10 = Pt3(this, t17).delete(t17);
    return this.size -= r10 ? 1 : 0, r10;
  };
  var It3 = function(t17) {
    return Ft3(this, t17).get(t17);
  };
  var kt3 = function(t17) {
    return Tt3(this, t17).has(t17);
  };
  var Rt3 = function(t17, r10) {
    var e22 = xt3(this, t17), n13 = e22.size;
    return e22.set(t17, r10), this.size += e22.size == n13 ? 0 : 1, this;
  };
  function Gt3(t17) {
    var r10 = -1, e22 = null == t17 ? 0 : t17.length;
    for (this.clear(); ++r10 < e22; ) {
      var n13 = t17[r10];
      this.set(n13[0], n13[1]);
    }
  }
  Gt3.prototype.clear = Ct3, Gt3.prototype.delete = Et3, Gt3.prototype.get = It3, Gt3.prototype.has = kt3, Gt3.prototype.set = Rt3;
  var Mt3 = Gt3;
  function Nt3(t17, r10) {
    if ("function" != typeof t17 || null != r10 && "function" != typeof r10)
      throw new TypeError("Expected a function");
    var e22 = function() {
      var n13 = arguments, o13 = r10 ? r10.apply(this, n13) : n13[0], a10 = e22.cache;
      if (a10.has(o13))
        return a10.get(o13);
      var i11 = t17.apply(this, n13);
      return e22.cache = a10.set(o13, i11) || a10, i11;
    };
    return e22.cache = new (Nt3.Cache || Mt3)(), e22;
  }
  Nt3.Cache = Mt3;
  var Ut3 = Nt3;
  var qt3 = /[^.[\]]+|\[(?:(-?\d+(?:\.\d+)?)|(["'])((?:(?!\2)[^\\]|\\.)*?)\2)\]|(?=(?:\.|\[\])(?:\.|\[\]|$))/g;
  var Bt3 = /\\(\\)?/g;
  var Dt3 = function(t17) {
    var r10 = Ut3(t17, function(t18) {
      return 500 === e22.size && e22.clear(), t18;
    }), e22 = r10.cache;
    return r10;
  }(function(t17) {
    var r10 = [];
    return 46 === t17.charCodeAt(0) && r10.push(""), t17.replace(qt3, function(t18, e22, n13, o13) {
      r10.push(n13 ? o13.replace(Bt3, "$1") : e22 || t18);
    }), r10;
  });
  var Ht3 = O5;
  var Jt3 = function(t17) {
    if ("string" == typeof t17 || Ht3(t17))
      return t17;
    var r10 = t17 + "";
    return "0" == r10 && 1 / t17 == -Infinity ? "-0" : r10;
  };
  var Kt3 = r5;
  var Lt3 = n7;
  var Qt3 = O5;
  var Vt3 = u5 ? u5.prototype : void 0;
  var Wt3 = Vt3 ? Vt3.toString : void 0;
  var Xt3 = function t10(r10) {
    if ("string" == typeof r10)
      return r10;
    if (Lt3(r10))
      return Kt3(r10, t10) + "";
    if (Qt3(r10))
      return Wt3 ? Wt3.call(r10) : "";
    var e22 = r10 + "";
    return "0" == e22 && 1 / r10 == -Infinity ? "-0" : e22;
  };
  var Yt3 = Xt3;
  var Zt3 = r5;
  var tr3 = e6;
  var rr3 = n7;
  var er3 = O5;
  var nr3 = Dt3;
  var or3 = Jt3;
  var ar3 = function(t17) {
    return null == t17 ? "" : Yt3(t17);
  };
  var ir3 = function(t17) {
    return rr3(t17) ? Zt3(t17, or3) : er3(t17) ? [t17] : tr3(nr3(ar3(t17)));
  };

  // http-url:https://cdn.jsdelivr.net/npm/cytoscape@3.26.0/+esm
  var i6 = o3;
  var o7 = cr;
  var s6 = gr;
  var l6 = ir3;
  function u6(e22) {
    return e22 && "object" == typeof e22 && "default" in e22 ? e22 : { default: e22 };
  }
  var c6 = u6(U);
  var d7 = u6(i6);
  var h6 = u6(o7);
  var p6 = u6(s6);
  var f6 = u6(l6);
  function g6(e22) {
    return g6 = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(e23) {
      return typeof e23;
    } : function(e23) {
      return e23 && "function" == typeof Symbol && e23.constructor === Symbol && e23 !== Symbol.prototype ? "symbol" : typeof e23;
    }, g6(e22);
  }
  function v6(e22, t17) {
    if (!(e22 instanceof t17))
      throw new TypeError("Cannot call a class as a function");
  }
  function y6(e22, t17) {
    for (var n13 = 0; n13 < t17.length; n13++) {
      var r10 = t17[n13];
      r10.enumerable = r10.enumerable || false, r10.configurable = true, "value" in r10 && (r10.writable = true), Object.defineProperty(e22, r10.key, r10);
    }
  }
  function m7(e22, t17, n13) {
    return t17 && y6(e22.prototype, t17), n13 && y6(e22, n13), Object.defineProperty(e22, "prototype", { writable: false }), e22;
  }
  function b6(e22, t17, n13) {
    return t17 in e22 ? Object.defineProperty(e22, t17, { value: n13, enumerable: true, configurable: true, writable: true }) : e22[t17] = n13, e22;
  }
  function x6(e22, t17) {
    return function(e23) {
      if (Array.isArray(e23))
        return e23;
    }(e22) || function(e23, t18) {
      var n13 = null == e23 ? null : "undefined" != typeof Symbol && e23[Symbol.iterator] || e23["@@iterator"];
      if (null == n13)
        return;
      var r10, a10, i11 = [], o13 = true, s11 = false;
      try {
        for (n13 = n13.call(e23); !(o13 = (r10 = n13.next()).done) && (i11.push(r10.value), !t18 || i11.length !== t18); o13 = true)
          ;
      } catch (e24) {
        s11 = true, a10 = e24;
      } finally {
        try {
          o13 || null == n13.return || n13.return();
        } finally {
          if (s11)
            throw a10;
        }
      }
      return i11;
    }(e22, t17) || function(e23, t18) {
      if (!e23)
        return;
      if ("string" == typeof e23)
        return w6(e23, t18);
      var n13 = Object.prototype.toString.call(e23).slice(8, -1);
      "Object" === n13 && e23.constructor && (n13 = e23.constructor.name);
      if ("Map" === n13 || "Set" === n13)
        return Array.from(e23);
      if ("Arguments" === n13 || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n13))
        return w6(e23, t18);
    }(e22, t17) || function() {
      throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.");
    }();
  }
  function w6(e22, t17) {
    (null == t17 || t17 > e22.length) && (t17 = e22.length);
    for (var n13 = 0, r10 = new Array(t17); n13 < t17; n13++)
      r10[n13] = e22[n13];
    return r10;
  }
  var E6 = "undefined" == typeof window ? null : window;
  var k5 = E6 ? E6.navigator : null;
  E6 && E6.document;
  var C5 = g6("");
  var S6 = g6({});
  var D5 = g6(function() {
  });
  var P6 = "undefined" == typeof HTMLElement ? "undefined" : g6(HTMLElement);
  var T6 = function(e22) {
    return e22 && e22.instanceString && B4(e22.instanceString) ? e22.instanceString() : null;
  };
  var M6 = function(e22) {
    return null != e22 && g6(e22) == C5;
  };
  var B4 = function(e22) {
    return null != e22 && g6(e22) === D5;
  };
  var _5 = function(e22) {
    return !L5(e22) && (Array.isArray ? Array.isArray(e22) : null != e22 && e22 instanceof Array);
  };
  var N6 = function(e22) {
    return null != e22 && g6(e22) === S6 && !_5(e22) && e22.constructor === Object;
  };
  var I6 = function(e22) {
    return null != e22 && g6(e22) === g6(1) && !isNaN(e22);
  };
  var z5 = function(e22) {
    return "undefined" === P6 ? void 0 : null != e22 && e22 instanceof HTMLElement;
  };
  var L5 = function(e22) {
    return A6(e22) || O6(e22);
  };
  var A6 = function(e22) {
    return "collection" === T6(e22) && e22._private.single;
  };
  var O6 = function(e22) {
    return "collection" === T6(e22) && !e22._private.single;
  };
  var R4 = function(e22) {
    return "core" === T6(e22);
  };
  var V5 = function(e22) {
    return "stylesheet" === T6(e22);
  };
  var F6 = function(e22) {
    return null == e22 || !("" !== e22 && !e22.match(/^\s+$/));
  };
  var q5 = function(e22) {
    return function(e23) {
      return null != e23 && g6(e23) === S6;
    }(e22) && B4(e22.then);
  };
  var j6 = function(e22, t17) {
    t17 || (t17 = function() {
      if (1 === arguments.length)
        return arguments[0];
      if (0 === arguments.length)
        return "undefined";
      for (var e23 = [], t18 = 0; t18 < arguments.length; t18++)
        e23.push(arguments[t18]);
      return e23.join("$");
    });
    var n13 = function n14() {
      var r10, a10 = arguments, i11 = t17.apply(this, a10), o13 = n14.cache;
      return (r10 = o13[i11]) || (r10 = o13[i11] = e22.apply(this, a10)), r10;
    };
    return n13.cache = {}, n13;
  };
  var Y4 = j6(function(e22) {
    return e22.replace(/([A-Z])/g, function(e23) {
      return "-" + e23.toLowerCase();
    });
  });
  var X4 = j6(function(e22) {
    return e22.replace(/(-\w)/g, function(e23) {
      return e23[1].toUpperCase();
    });
  });
  var W5 = j6(function(e22, t17) {
    return e22 + t17[0].toUpperCase() + t17.substring(1);
  }, function(e22, t17) {
    return e22 + "$" + t17;
  });
  var H4 = function(e22) {
    return F6(e22) ? e22 : e22.charAt(0).toUpperCase() + e22.substring(1);
  };
  var K4 = "(?:[-+]?(?:(?:\\d+|\\d*\\.\\d+)(?:[Ee][+-]?\\d+)?))";
  var G4 = "rgb[a]?\\((" + K4 + "[%]?)\\s*,\\s*(" + K4 + "[%]?)\\s*,\\s*(" + K4 + "[%]?)(?:\\s*,\\s*(" + K4 + "))?\\)";
  var U5 = "rgb[a]?\\((?:" + K4 + "[%]?)\\s*,\\s*(?:" + K4 + "[%]?)\\s*,\\s*(?:" + K4 + "[%]?)(?:\\s*,\\s*(?:" + K4 + "))?\\)";
  var Z4 = "hsl[a]?\\((" + K4 + ")\\s*,\\s*(" + K4 + "[%])\\s*,\\s*(" + K4 + "[%])(?:\\s*,\\s*(" + K4 + "))?\\)";
  var $6 = "hsl[a]?\\((?:" + K4 + ")\\s*,\\s*(?:" + K4 + "[%])\\s*,\\s*(?:" + K4 + "[%])(?:\\s*,\\s*(?:" + K4 + "))?\\)";
  var Q4 = function(e22, t17) {
    return e22 < t17 ? -1 : e22 > t17 ? 1 : 0;
  };
  var J4 = null != Object.assign ? Object.assign.bind(Object) : function(e22) {
    for (var t17 = arguments, n13 = 1; n13 < t17.length; n13++) {
      var r10 = t17[n13];
      if (null != r10)
        for (var a10 = Object.keys(r10), i11 = 0; i11 < a10.length; i11++) {
          var o13 = a10[i11];
          e22[o13] = r10[o13];
        }
    }
    return e22;
  };
  var ee = function(e22) {
    return (_5(e22) ? e22 : null) || function(e23) {
      return te[e23.toLowerCase()];
    }(e22) || function(e23) {
      if ((4 === e23.length || 7 === e23.length) && "#" === e23[0]) {
        var t17, n13, r10, a10 = 16;
        return 4 === e23.length ? (t17 = parseInt(e23[1] + e23[1], a10), n13 = parseInt(e23[2] + e23[2], a10), r10 = parseInt(e23[3] + e23[3], a10)) : (t17 = parseInt(e23[1] + e23[2], a10), n13 = parseInt(e23[3] + e23[4], a10), r10 = parseInt(e23[5] + e23[6], a10)), [t17, n13, r10];
      }
    }(e22) || function(e23) {
      var t17, n13 = new RegExp("^" + G4 + "$").exec(e23);
      if (n13) {
        t17 = [];
        for (var r10 = [], a10 = 1; a10 <= 3; a10++) {
          var i11 = n13[a10];
          if ("%" === i11[i11.length - 1] && (r10[a10] = true), i11 = parseFloat(i11), r10[a10] && (i11 = i11 / 100 * 255), i11 < 0 || i11 > 255)
            return;
          t17.push(Math.floor(i11));
        }
        var o13 = r10[1] || r10[2] || r10[3], s11 = r10[1] && r10[2] && r10[3];
        if (o13 && !s11)
          return;
        var l11 = n13[4];
        if (void 0 !== l11) {
          if ((l11 = parseFloat(l11)) < 0 || l11 > 1)
            return;
          t17.push(l11);
        }
      }
      return t17;
    }(e22) || function(e23) {
      var t17, n13, r10, a10, i11, o13, s11, l11;
      function u10(e24, t18, n14) {
        return n14 < 0 && (n14 += 1), n14 > 1 && (n14 -= 1), n14 < 1 / 6 ? e24 + 6 * (t18 - e24) * n14 : n14 < 0.5 ? t18 : n14 < 2 / 3 ? e24 + (t18 - e24) * (2 / 3 - n14) * 6 : e24;
      }
      var c10 = new RegExp("^" + Z4 + "$").exec(e23);
      if (c10) {
        if ((n13 = parseInt(c10[1])) < 0 ? n13 = (360 - -1 * n13 % 360) % 360 : n13 > 360 && (n13 %= 360), n13 /= 360, (r10 = parseFloat(c10[2])) < 0 || r10 > 100)
          return;
        if (r10 /= 100, (a10 = parseFloat(c10[3])) < 0 || a10 > 100)
          return;
        if (a10 /= 100, void 0 !== (i11 = c10[4]) && ((i11 = parseFloat(i11)) < 0 || i11 > 1))
          return;
        if (0 === r10)
          o13 = s11 = l11 = Math.round(255 * a10);
        else {
          var d12 = a10 < 0.5 ? a10 * (1 + r10) : a10 + r10 - a10 * r10, h10 = 2 * a10 - d12;
          o13 = Math.round(255 * u10(h10, d12, n13 + 1 / 3)), s11 = Math.round(255 * u10(h10, d12, n13)), l11 = Math.round(255 * u10(h10, d12, n13 - 1 / 3));
        }
        t17 = [o13, s11, l11, i11];
      }
      return t17;
    }(e22);
  };
  var te = { transparent: [0, 0, 0, 0], aliceblue: [240, 248, 255], antiquewhite: [250, 235, 215], aqua: [0, 255, 255], aquamarine: [127, 255, 212], azure: [240, 255, 255], beige: [245, 245, 220], bisque: [255, 228, 196], black: [0, 0, 0], blanchedalmond: [255, 235, 205], blue: [0, 0, 255], blueviolet: [138, 43, 226], brown: [165, 42, 42], burlywood: [222, 184, 135], cadetblue: [95, 158, 160], chartreuse: [127, 255, 0], chocolate: [210, 105, 30], coral: [255, 127, 80], cornflowerblue: [100, 149, 237], cornsilk: [255, 248, 220], crimson: [220, 20, 60], cyan: [0, 255, 255], darkblue: [0, 0, 139], darkcyan: [0, 139, 139], darkgoldenrod: [184, 134, 11], darkgray: [169, 169, 169], darkgreen: [0, 100, 0], darkgrey: [169, 169, 169], darkkhaki: [189, 183, 107], darkmagenta: [139, 0, 139], darkolivegreen: [85, 107, 47], darkorange: [255, 140, 0], darkorchid: [153, 50, 204], darkred: [139, 0, 0], darksalmon: [233, 150, 122], darkseagreen: [143, 188, 143], darkslateblue: [72, 61, 139], darkslategray: [47, 79, 79], darkslategrey: [47, 79, 79], darkturquoise: [0, 206, 209], darkviolet: [148, 0, 211], deeppink: [255, 20, 147], deepskyblue: [0, 191, 255], dimgray: [105, 105, 105], dimgrey: [105, 105, 105], dodgerblue: [30, 144, 255], firebrick: [178, 34, 34], floralwhite: [255, 250, 240], forestgreen: [34, 139, 34], fuchsia: [255, 0, 255], gainsboro: [220, 220, 220], ghostwhite: [248, 248, 255], gold: [255, 215, 0], goldenrod: [218, 165, 32], gray: [128, 128, 128], grey: [128, 128, 128], green: [0, 128, 0], greenyellow: [173, 255, 47], honeydew: [240, 255, 240], hotpink: [255, 105, 180], indianred: [205, 92, 92], indigo: [75, 0, 130], ivory: [255, 255, 240], khaki: [240, 230, 140], lavender: [230, 230, 250], lavenderblush: [255, 240, 245], lawngreen: [124, 252, 0], lemonchiffon: [255, 250, 205], lightblue: [173, 216, 230], lightcoral: [240, 128, 128], lightcyan: [224, 255, 255], lightgoldenrodyellow: [250, 250, 210], lightgray: [211, 211, 211], lightgreen: [144, 238, 144], lightgrey: [211, 211, 211], lightpink: [255, 182, 193], lightsalmon: [255, 160, 122], lightseagreen: [32, 178, 170], lightskyblue: [135, 206, 250], lightslategray: [119, 136, 153], lightslategrey: [119, 136, 153], lightsteelblue: [176, 196, 222], lightyellow: [255, 255, 224], lime: [0, 255, 0], limegreen: [50, 205, 50], linen: [250, 240, 230], magenta: [255, 0, 255], maroon: [128, 0, 0], mediumaquamarine: [102, 205, 170], mediumblue: [0, 0, 205], mediumorchid: [186, 85, 211], mediumpurple: [147, 112, 219], mediumseagreen: [60, 179, 113], mediumslateblue: [123, 104, 238], mediumspringgreen: [0, 250, 154], mediumturquoise: [72, 209, 204], mediumvioletred: [199, 21, 133], midnightblue: [25, 25, 112], mintcream: [245, 255, 250], mistyrose: [255, 228, 225], moccasin: [255, 228, 181], navajowhite: [255, 222, 173], navy: [0, 0, 128], oldlace: [253, 245, 230], olive: [128, 128, 0], olivedrab: [107, 142, 35], orange: [255, 165, 0], orangered: [255, 69, 0], orchid: [218, 112, 214], palegoldenrod: [238, 232, 170], palegreen: [152, 251, 152], paleturquoise: [175, 238, 238], palevioletred: [219, 112, 147], papayawhip: [255, 239, 213], peachpuff: [255, 218, 185], peru: [205, 133, 63], pink: [255, 192, 203], plum: [221, 160, 221], powderblue: [176, 224, 230], purple: [128, 0, 128], red: [255, 0, 0], rosybrown: [188, 143, 143], royalblue: [65, 105, 225], saddlebrown: [139, 69, 19], salmon: [250, 128, 114], sandybrown: [244, 164, 96], seagreen: [46, 139, 87], seashell: [255, 245, 238], sienna: [160, 82, 45], silver: [192, 192, 192], skyblue: [135, 206, 235], slateblue: [106, 90, 205], slategray: [112, 128, 144], slategrey: [112, 128, 144], snow: [255, 250, 250], springgreen: [0, 255, 127], steelblue: [70, 130, 180], tan: [210, 180, 140], teal: [0, 128, 128], thistle: [216, 191, 216], tomato: [255, 99, 71], turquoise: [64, 224, 208], violet: [238, 130, 238], wheat: [245, 222, 179], white: [255, 255, 255], whitesmoke: [245, 245, 245], yellow: [255, 255, 0], yellowgreen: [154, 205, 50] };
  var ne = function(e22) {
    for (var t17 = e22.map, n13 = e22.keys, r10 = n13.length, a10 = 0; a10 < r10; a10++) {
      var i11 = n13[a10];
      if (N6(i11))
        throw Error("Tried to set map with object key");
      a10 < n13.length - 1 ? (null == t17[i11] && (t17[i11] = {}), t17 = t17[i11]) : t17[i11] = e22.value;
    }
  };
  var re = function(e22) {
    for (var t17 = e22.map, n13 = e22.keys, r10 = n13.length, a10 = 0; a10 < r10; a10++) {
      var i11 = n13[a10];
      if (N6(i11))
        throw Error("Tried to get map with object key");
      if (null == (t17 = t17[i11]))
        return t17;
    }
    return t17;
  };
  var ae = E6 ? E6.performance : null;
  var ie = ae && ae.now ? function() {
    return ae.now();
  } : function() {
    return Date.now();
  };
  var oe = function() {
    if (E6) {
      if (E6.requestAnimationFrame)
        return function(e22) {
          E6.requestAnimationFrame(e22);
        };
      if (E6.mozRequestAnimationFrame)
        return function(e22) {
          E6.mozRequestAnimationFrame(e22);
        };
      if (E6.webkitRequestAnimationFrame)
        return function(e22) {
          E6.webkitRequestAnimationFrame(e22);
        };
      if (E6.msRequestAnimationFrame)
        return function(e22) {
          E6.msRequestAnimationFrame(e22);
        };
    }
    return function(e22) {
      e22 && setTimeout(function() {
        e22(ie());
      }, 1e3 / 60);
    };
  }();
  var se = function(e22) {
    return oe(e22);
  };
  var le = ie;
  var ue = 9261;
  var ce = 5381;
  var de = function(e22) {
    for (var t17, n13 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : ue; !(t17 = e22.next()).done; )
      n13 = 65599 * n13 + t17.value | 0;
    return n13;
  };
  var he = function(e22) {
    return 65599 * (arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : ue) + e22 | 0;
  };
  var pe = function(e22) {
    var t17 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : ce;
    return (t17 << 5) + t17 + e22 | 0;
  };
  var fe = function(e22) {
    return 2097152 * e22[0] + e22[1];
  };
  var ge = function(e22, t17) {
    return [he(e22[0], t17[0]), pe(e22[1], t17[1])];
  };
  var ve = function(e22, t17) {
    var n13 = { value: 0, done: false }, r10 = 0, a10 = e22.length;
    return de({ next: function() {
      return r10 < a10 ? n13.value = e22.charCodeAt(r10++) : n13.done = true, n13;
    } }, t17);
  };
  var ye = function() {
    return me(arguments);
  };
  var me = function(e22) {
    for (var t17, n13 = 0; n13 < e22.length; n13++) {
      var r10 = e22[n13];
      t17 = 0 === n13 ? ve(r10) : ve(r10, t17);
    }
    return t17;
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
  var Pe = function(e22) {
    throw new Error(e22);
  };
  var Te = function(e22) {
    if (void 0 === e22)
      return be;
    be = !!e22;
  };
  var Me = function(e22) {
    Te() && (xe ? console.warn(e22) : (console.log(e22), we && console.trace()));
  };
  var Be = function(e22) {
    return null == e22 ? e22 : _5(e22) ? e22.slice() : N6(e22) ? function(e23) {
      return J4({}, e23);
    }(e22) : e22;
  };
  var _e = function(e22, t17) {
    for (t17 = e22 = ""; e22++ < 36; t17 += 51 * e22 & 52 ? (15 ^ e22 ? 8 ^ Math.random() * (20 ^ e22 ? 16 : 4) : 4).toString(16) : "-")
      ;
    return t17;
  };
  var Ne = {};
  var Ie = function() {
    return Ne;
  };
  var ze = function(e22) {
    var t17 = Object.keys(e22);
    return function(n13) {
      for (var r10 = {}, a10 = 0; a10 < t17.length; a10++) {
        var i11 = t17[a10], o13 = null == n13 ? void 0 : n13[i11];
        r10[i11] = void 0 === o13 ? e22[i11] : o13;
      }
      return r10;
    };
  };
  var Le = function(e22, t17, n13) {
    for (var r10 = e22.length - 1; r10 >= 0 && (e22[r10] !== t17 || (e22.splice(r10, 1), !n13)); r10--)
      ;
  };
  var Ae = function(e22) {
    e22.splice(0, e22.length);
  };
  var Oe = function(e22, t17, n13) {
    return n13 && (t17 = W5(n13, t17)), e22[t17];
  };
  var Re = function(e22, t17, n13, r10) {
    n13 && (t17 = W5(n13, t17)), e22[t17] = r10;
  };
  var Ve = "undefined" != typeof Map ? Map : function() {
    function e22() {
      v6(this, e22), this._obj = {};
    }
    return m7(e22, [{ key: "set", value: function(e23, t17) {
      return this._obj[e23] = t17, this;
    } }, { key: "delete", value: function(e23) {
      return this._obj[e23] = void 0, this;
    } }, { key: "clear", value: function() {
      this._obj = {};
    } }, { key: "has", value: function(e23) {
      return void 0 !== this._obj[e23];
    } }, { key: "get", value: function(e23) {
      return this._obj[e23];
    } }]), e22;
  }();
  var Fe = function() {
    function e22(t17) {
      if (v6(this, e22), this._obj = /* @__PURE__ */ Object.create(null), this.size = 0, null != t17) {
        var n13;
        n13 = null != t17.instanceString && t17.instanceString() === this.instanceString() ? t17.toArray() : t17;
        for (var r10 = 0; r10 < n13.length; r10++)
          this.add(n13[r10]);
      }
    }
    return m7(e22, [{ key: "instanceString", value: function() {
      return "set";
    } }, { key: "add", value: function(e23) {
      var t17 = this._obj;
      1 !== t17[e23] && (t17[e23] = 1, this.size++);
    } }, { key: "delete", value: function(e23) {
      var t17 = this._obj;
      1 === t17[e23] && (t17[e23] = 0, this.size--);
    } }, { key: "clear", value: function() {
      this._obj = /* @__PURE__ */ Object.create(null);
    } }, { key: "has", value: function(e23) {
      return 1 === this._obj[e23];
    } }, { key: "toArray", value: function() {
      var e23 = this;
      return Object.keys(this._obj).filter(function(t17) {
        return e23.has(t17);
      });
    } }, { key: "forEach", value: function(e23, t17) {
      return this.toArray().forEach(e23, t17);
    } }]), e22;
  }();
  var qe = "undefined" !== ("undefined" == typeof Set ? "undefined" : g6(Set)) ? Set : Fe;
  var je = function(e22, t17) {
    var n13 = !(arguments.length > 2 && void 0 !== arguments[2]) || arguments[2];
    if (void 0 !== e22 && void 0 !== t17 && R4(e22)) {
      var r10 = t17.group;
      if (null == r10 && (r10 = t17.data && null != t17.data.source && null != t17.data.target ? "edges" : "nodes"), "nodes" === r10 || "edges" === r10) {
        this.length = 1, this[0] = this;
        var a10 = this._private = { cy: e22, single: true, data: t17.data || {}, position: t17.position || { x: 0, y: 0 }, autoWidth: void 0, autoHeight: void 0, autoPadding: void 0, compoundBoundsClean: false, listeners: [], group: r10, style: {}, rstyle: {}, styleCxts: [], styleKeys: {}, removed: true, selected: !!t17.selected, selectable: void 0 === t17.selectable || !!t17.selectable, locked: !!t17.locked, grabbed: false, grabbable: void 0 === t17.grabbable || !!t17.grabbable, pannable: void 0 === t17.pannable ? "edges" === r10 : !!t17.pannable, active: false, classes: new qe(), animation: { current: [], queue: [] }, rscratch: {}, scratch: t17.scratch || {}, edges: [], children: [], parent: t17.parent && t17.parent.isNode() ? t17.parent : null, traversalCache: {}, backgrounding: false, bbCache: null, bbCacheShift: { x: 0, y: 0 }, bodyBounds: null, overlayBounds: null, labelBounds: { all: null, source: null, target: null, main: null }, arrowBounds: { source: null, target: null, "mid-source": null, "mid-target": null } };
        if (null == a10.position.x && (a10.position.x = 0), null == a10.position.y && (a10.position.y = 0), t17.renderedPosition) {
          var i11 = t17.renderedPosition, o13 = e22.pan(), s11 = e22.zoom();
          a10.position = { x: (i11.x - o13.x) / s11, y: (i11.y - o13.y) / s11 };
        }
        var l11 = [];
        _5(t17.classes) ? l11 = t17.classes : M6(t17.classes) && (l11 = t17.classes.split(/\s+/));
        for (var u10 = 0, c10 = l11.length; u10 < c10; u10++) {
          var d12 = l11[u10];
          d12 && "" !== d12 && a10.classes.add(d12);
        }
        this.createEmitter();
        var h10 = t17.style || t17.css;
        h10 && (Me("Setting a `style` bypass at element creation should be done only when absolutely necessary.  Try to use the stylesheet instead."), this.style(h10)), (void 0 === n13 || n13) && this.restore();
      } else
        Pe("An element must be of type `nodes` or `edges`; you specified `" + r10 + "`");
    } else
      Pe("An element must have a core reference and parameters set");
  };
  var Ye = function(e22) {
    return e22 = { bfs: e22.bfs || !e22.dfs, dfs: e22.dfs || !e22.bfs }, function(t17, n13, r10) {
      var a10;
      N6(t17) && !L5(t17) && (t17 = (a10 = t17).roots || a10.root, n13 = a10.visit, r10 = a10.directed), r10 = 2 !== arguments.length || B4(n13) ? r10 : n13, n13 = B4(n13) ? n13 : function() {
      };
      for (var i11, o13 = this._private.cy, s11 = t17 = M6(t17) ? this.filter(t17) : t17, l11 = [], u10 = [], c10 = {}, d12 = {}, h10 = {}, p10 = 0, f11 = this.byGroup(), g9 = f11.nodes, v12 = f11.edges, y10 = 0; y10 < s11.length; y10++) {
        var m12 = s11[y10], b11 = m12.id();
        m12.isNode() && (l11.unshift(m12), e22.bfs && (h10[b11] = true, u10.push(m12)), d12[b11] = 0);
      }
      for (var x11 = function() {
        var t18 = e22.bfs ? l11.shift() : l11.pop(), a11 = t18.id();
        if (e22.dfs) {
          if (h10[a11])
            return "continue";
          h10[a11] = true, u10.push(t18);
        }
        var o14, s12 = d12[a11], f12 = c10[a11], y11 = null != f12 ? f12.source() : null, m13 = null != f12 ? f12.target() : null, b12 = null == f12 ? void 0 : t18.same(y11) ? m13[0] : y11[0];
        if (true === (o14 = n13(t18, f12, b12, p10++, s12)))
          return i11 = t18, "break";
        if (false === o14)
          return "break";
        for (var x12 = t18.connectedEdges().filter(function(e23) {
          return (!r10 || e23.source().same(t18)) && v12.has(e23);
        }), w11 = 0; w11 < x12.length; w11++) {
          var E11 = x12[w11], k11 = E11.connectedNodes().filter(function(e23) {
            return !e23.same(t18) && g9.has(e23);
          }), C10 = k11.id();
          0 === k11.length || h10[C10] || (k11 = k11[0], l11.push(k11), e22.bfs && (h10[C10] = true, u10.push(k11)), c10[C10] = E11, d12[C10] = d12[a11] + 1);
        }
      }; 0 !== l11.length; ) {
        var w10 = x11();
        if ("continue" !== w10 && "break" === w10)
          break;
      }
      for (var E10 = o13.collection(), k10 = 0; k10 < u10.length; k10++) {
        var C9 = u10[k10], S8 = c10[C9.id()];
        null != S8 && E10.push(S8), E10.push(C9);
      }
      return { path: o13.collection(E10), found: o13.collection(i11) };
    };
  };
  var Xe = { breadthFirstSearch: Ye({ bfs: true }), depthFirstSearch: Ye({ dfs: true }) };
  Xe.bfs = Xe.breadthFirstSearch, Xe.dfs = Xe.depthFirstSearch;
  var We = ze({ root: null, weight: function(e22) {
    return 1;
  }, directed: false });
  var He = { dijkstra: function(e22) {
    if (!N6(e22)) {
      var t17 = arguments;
      e22 = { root: t17[0], weight: t17[1], directed: t17[2] };
    }
    var n13 = We(e22), r10 = n13.root, a10 = n13.weight, i11 = n13.directed, o13 = this, s11 = a10, l11 = M6(r10) ? this.filter(r10)[0] : r10[0], u10 = {}, c10 = {}, h10 = {}, p10 = this.byGroup(), f11 = p10.nodes, g9 = p10.edges;
    g9.unmergeBy(function(e23) {
      return e23.isLoop();
    });
    for (var v12 = function(e23) {
      return u10[e23.id()];
    }, y10 = function(e23, t18) {
      u10[e23.id()] = t18, m12.updateItem(e23);
    }, m12 = new d7.default(function(e23, t18) {
      return v12(e23) - v12(t18);
    }), b11 = 0; b11 < f11.length; b11++) {
      var x11 = f11[b11];
      u10[x11.id()] = x11.same(l11) ? 0 : 1 / 0, m12.push(x11);
    }
    for (var w10 = function(e23, t18) {
      for (var n14, r11 = (i11 ? e23.edgesTo(t18) : e23.edgesWith(t18)).intersect(g9), a11 = 1 / 0, o14 = 0; o14 < r11.length; o14++) {
        var l12 = r11[o14], u11 = s11(l12);
        (u11 < a11 || !n14) && (a11 = u11, n14 = l12);
      }
      return { edge: n14, dist: a11 };
    }; m12.size() > 0; ) {
      var E10 = m12.pop(), k10 = v12(E10), C9 = E10.id();
      if (h10[C9] = k10, k10 !== 1 / 0)
        for (var S8 = E10.neighborhood().intersect(f11), D7 = 0; D7 < S8.length; D7++) {
          var P10 = S8[D7], T9 = P10.id(), B8 = w10(E10, P10), _7 = k10 + B8.dist;
          _7 < v12(P10) && (y10(P10, _7), c10[T9] = { node: E10, edge: B8.edge });
        }
    }
    return { distanceTo: function(e23) {
      var t18 = M6(e23) ? f11.filter(e23)[0] : e23[0];
      return h10[t18.id()];
    }, pathTo: function(e23) {
      var t18 = M6(e23) ? f11.filter(e23)[0] : e23[0], n14 = [], r11 = t18, a11 = r11.id();
      if (t18.length > 0)
        for (n14.unshift(t18); c10[a11]; ) {
          var i12 = c10[a11];
          n14.unshift(i12.edge), n14.unshift(i12.node), a11 = (r11 = i12.node).id();
        }
      return o13.spawn(n14);
    } };
  } };
  var Ke = { kruskal: function(e22) {
    e22 = e22 || function(e23) {
      return 1;
    };
    for (var t17 = this.byGroup(), n13 = t17.nodes, r10 = t17.edges, a10 = n13.length, i11 = new Array(a10), o13 = n13, s11 = function(e23) {
      for (var t18 = 0; t18 < i11.length; t18++) {
        if (i11[t18].has(e23))
          return t18;
      }
    }, l11 = 0; l11 < a10; l11++)
      i11[l11] = this.spawn(n13[l11]);
    for (var u10 = r10.sort(function(t18, n14) {
      return e22(t18) - e22(n14);
    }), c10 = 0; c10 < u10.length; c10++) {
      var d12 = u10[c10], h10 = d12.source()[0], p10 = d12.target()[0], f11 = s11(h10), g9 = s11(p10), v12 = i11[f11], y10 = i11[g9];
      f11 !== g9 && (o13.merge(d12), v12.merge(y10), i11.splice(g9, 1));
    }
    return o13;
  } };
  var Ge = ze({ root: null, goal: null, weight: function(e22) {
    return 1;
  }, heuristic: function(e22) {
    return 0;
  }, directed: false });
  var Ue = { aStar: function(e22) {
    var t17 = this.cy(), n13 = Ge(e22), r10 = n13.root, a10 = n13.goal, i11 = n13.heuristic, o13 = n13.directed, s11 = n13.weight;
    r10 = t17.collection(r10)[0], a10 = t17.collection(a10)[0];
    var l11, u10, c10 = r10.id(), h10 = a10.id(), p10 = {}, f11 = {}, g9 = {}, v12 = new d7.default(function(e23, t18) {
      return f11[e23.id()] - f11[t18.id()];
    }), y10 = new qe(), m12 = {}, b11 = {}, x11 = function(e23, t18) {
      v12.push(e23), y10.add(t18);
    };
    x11(r10, c10), p10[c10] = 0, f11[c10] = i11(r10);
    for (var w10, E10 = 0; v12.size() > 0; ) {
      if (l11 = v12.pop(), u10 = l11.id(), y10.delete(u10), E10++, u10 === h10) {
        for (var k10 = [], C9 = a10, S8 = h10, D7 = b11[S8]; k10.unshift(C9), null != D7 && k10.unshift(D7), null != (C9 = m12[S8]); )
          D7 = b11[S8 = C9.id()];
        return { found: true, distance: p10[u10], path: this.spawn(k10), steps: E10 };
      }
      g9[u10] = true;
      for (var P10 = l11._private.edges, T9 = 0; T9 < P10.length; T9++) {
        var M9 = P10[T9];
        if (this.hasElementWithId(M9.id()) && (!o13 || M9.data("source") === u10)) {
          var B8 = M9.source(), _7 = M9.target(), N8 = B8.id() !== u10 ? B8 : _7, I8 = N8.id();
          if (this.hasElementWithId(I8) && !g9[I8]) {
            var z8 = p10[u10] + s11(M9);
            w10 = I8, y10.has(w10) ? z8 < p10[I8] && (p10[I8] = z8, f11[I8] = z8 + i11(N8), m12[I8] = l11, b11[I8] = M9) : (p10[I8] = z8, f11[I8] = z8 + i11(N8), x11(N8, I8), m12[I8] = l11, b11[I8] = M9);
          }
        }
      }
    }
    return { found: false, distance: void 0, path: void 0, steps: E10 };
  } };
  var Ze = ze({ weight: function(e22) {
    return 1;
  }, directed: false });
  var $e = { floydWarshall: function(e22) {
    for (var t17 = this.cy(), n13 = Ze(e22), r10 = n13.weight, a10 = n13.directed, i11 = r10, o13 = this.byGroup(), s11 = o13.nodes, l11 = o13.edges, u10 = s11.length, c10 = u10 * u10, d12 = function(e23) {
      return s11.indexOf(e23);
    }, h10 = function(e23) {
      return s11[e23];
    }, p10 = new Array(c10), f11 = 0; f11 < c10; f11++) {
      var g9 = f11 % u10, v12 = (f11 - g9) / u10;
      p10[f11] = v12 === g9 ? 0 : 1 / 0;
    }
    for (var y10 = new Array(c10), m12 = new Array(c10), b11 = 0; b11 < l11.length; b11++) {
      var x11 = l11[b11], w10 = x11.source()[0], E10 = x11.target()[0];
      if (w10 !== E10) {
        var k10 = d12(w10), C9 = d12(E10), S8 = k10 * u10 + C9, D7 = i11(x11);
        if (p10[S8] > D7 && (p10[S8] = D7, y10[S8] = C9, m12[S8] = x11), !a10) {
          var P10 = C9 * u10 + k10;
          !a10 && p10[P10] > D7 && (p10[P10] = D7, y10[P10] = k10, m12[P10] = x11);
        }
      }
    }
    for (var T9 = 0; T9 < u10; T9++)
      for (var B8 = 0; B8 < u10; B8++)
        for (var _7 = B8 * u10 + T9, N8 = 0; N8 < u10; N8++) {
          var I8 = B8 * u10 + N8, z8 = T9 * u10 + N8;
          p10[_7] + p10[z8] < p10[I8] && (p10[I8] = p10[_7] + p10[z8], y10[I8] = y10[_7]);
        }
    var L10 = function(e23) {
      return d12(function(e24) {
        return (M6(e24) ? t17.filter(e24) : e24)[0];
      }(e23));
    }, A10 = { distance: function(e23, t18) {
      var n14 = L10(e23), r11 = L10(t18);
      return p10[n14 * u10 + r11];
    }, path: function(e23, n14) {
      var r11 = L10(e23), a11 = L10(n14), i12 = h10(r11);
      if (r11 === a11)
        return i12.collection();
      if (null == y10[r11 * u10 + a11])
        return t17.collection();
      var o14, s12 = t17.collection(), l12 = r11;
      for (s12.merge(i12); r11 !== a11; )
        l12 = r11, r11 = y10[r11 * u10 + a11], o14 = m12[l12 * u10 + r11], s12.merge(o14), s12.merge(h10(r11));
      return s12;
    } };
    return A10;
  } };
  var Qe = ze({ weight: function(e22) {
    return 1;
  }, directed: false, root: null });
  var Je = { bellmanFord: function(e22) {
    var t17 = this, n13 = Qe(e22), r10 = n13.weight, a10 = n13.directed, i11 = n13.root, o13 = r10, s11 = this, l11 = this.cy(), u10 = this.byGroup(), c10 = u10.edges, d12 = u10.nodes, h10 = d12.length, p10 = new Ve(), f11 = false, g9 = [];
    i11 = l11.collection(i11)[0], c10.unmergeBy(function(e23) {
      return e23.isLoop();
    });
    for (var v12 = c10.length, y10 = function(e23) {
      var t18 = p10.get(e23.id());
      return t18 || (t18 = {}, p10.set(e23.id(), t18)), t18;
    }, m12 = function(e23) {
      return (M6(e23) ? l11.$(e23) : e23)[0];
    }, b11 = 0; b11 < h10; b11++) {
      var x11 = d12[b11], w10 = y10(x11);
      x11.same(i11) ? w10.dist = 0 : w10.dist = 1 / 0, w10.pred = null, w10.edge = null;
    }
    for (var E10 = false, k10 = function(e23, t18, n14, r11, a11, i12) {
      var o14 = r11.dist + i12;
      o14 < a11.dist && !n14.same(r11.edge) && (a11.dist = o14, a11.pred = e23, a11.edge = n14, E10 = true);
    }, C9 = 1; C9 < h10; C9++) {
      E10 = false;
      for (var S8 = 0; S8 < v12; S8++) {
        var D7 = c10[S8], P10 = D7.source(), T9 = D7.target(), B8 = o13(D7), _7 = y10(P10), N8 = y10(T9);
        k10(P10, 0, D7, _7, N8, B8), a10 || k10(T9, 0, D7, N8, _7, B8);
      }
      if (!E10)
        break;
    }
    if (E10)
      for (var I8 = [], z8 = 0; z8 < v12; z8++) {
        var L10 = c10[z8], A10 = L10.source(), O9 = L10.target(), R8 = o13(L10), V8 = y10(A10).dist, F9 = y10(O9).dist;
        if (V8 + R8 < F9 || !a10 && F9 + R8 < V8) {
          if (f11 || (Me("Graph contains a negative weight cycle for Bellman-Ford"), f11 = true), false === e22.findNegativeWeightCycles)
            break;
          var q8 = [];
          V8 + R8 < F9 && q8.push(A10), !a10 && F9 + R8 < V8 && q8.push(O9);
          for (var j9 = q8.length, Y6 = 0; Y6 < j9; Y6++) {
            var X6 = q8[Y6], W8 = [X6];
            W8.push(y10(X6).edge);
            for (var H8 = y10(X6).pred; -1 === W8.indexOf(H8); )
              W8.push(H8), W8.push(y10(H8).edge), H8 = y10(H8).pred;
            for (var K6 = (W8 = W8.slice(W8.indexOf(H8)))[0].id(), G6 = 0, U7 = 2; U7 < W8.length; U7 += 2)
              W8[U7].id() < K6 && (K6 = W8[U7].id(), G6 = U7);
            (W8 = W8.slice(G6).concat(W8.slice(0, G6))).push(W8[0]);
            var Z6 = W8.map(function(e23) {
              return e23.id();
            }).join(",");
            -1 === I8.indexOf(Z6) && (g9.push(s11.spawn(W8)), I8.push(Z6));
          }
        }
      }
    return { distanceTo: function(e23) {
      return y10(m12(e23)).dist;
    }, pathTo: function(e23) {
      for (var n14 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : i11, r11 = [], a11 = m12(e23); ; ) {
        if (null == a11)
          return t17.spawn();
        var o14 = y10(a11), l12 = o14.edge, u11 = o14.pred;
        if (r11.unshift(a11[0]), a11.same(n14) && r11.length > 0)
          break;
        null != l12 && r11.unshift(l12), a11 = u11;
      }
      return s11.spawn(r11);
    }, hasNegativeWeightCycle: f11, negativeWeightCycles: g9 };
  } };
  var et4 = Math.sqrt(2);
  var tt4 = function(e22, t17, n13) {
    0 === n13.length && Pe("Karger-Stein must be run on a connected (sub)graph");
    for (var r10 = n13[e22], a10 = r10[1], i11 = r10[2], o13 = t17[a10], s11 = t17[i11], l11 = n13, u10 = l11.length - 1; u10 >= 0; u10--) {
      var c10 = l11[u10], d12 = c10[1], h10 = c10[2];
      (t17[d12] === o13 && t17[h10] === s11 || t17[d12] === s11 && t17[h10] === o13) && l11.splice(u10, 1);
    }
    for (var p10 = 0; p10 < l11.length; p10++) {
      var f11 = l11[p10];
      f11[1] === s11 ? (l11[p10] = f11.slice(), l11[p10][1] = o13) : f11[2] === s11 && (l11[p10] = f11.slice(), l11[p10][2] = o13);
    }
    for (var g9 = 0; g9 < t17.length; g9++)
      t17[g9] === s11 && (t17[g9] = o13);
    return l11;
  };
  var nt4 = function(e22, t17, n13, r10) {
    for (; n13 > r10; ) {
      var a10 = Math.floor(Math.random() * t17.length);
      t17 = tt4(a10, e22, t17), n13--;
    }
    return t17;
  };
  var rt4 = { kargerStein: function() {
    var e22 = this, t17 = this.byGroup(), n13 = t17.nodes, r10 = t17.edges;
    r10.unmergeBy(function(e23) {
      return e23.isLoop();
    });
    var a10 = n13.length, i11 = r10.length, o13 = Math.ceil(Math.pow(Math.log(a10) / Math.LN2, 2)), s11 = Math.floor(a10 / et4);
    if (!(a10 < 2)) {
      for (var l11 = [], u10 = 0; u10 < i11; u10++) {
        var c10 = r10[u10];
        l11.push([u10, n13.indexOf(c10.source()), n13.indexOf(c10.target())]);
      }
      for (var d12 = 1 / 0, h10 = [], p10 = new Array(a10), f11 = new Array(a10), g9 = new Array(a10), v12 = function(e23, t18) {
        for (var n14 = 0; n14 < a10; n14++)
          t18[n14] = e23[n14];
      }, y10 = 0; y10 <= o13; y10++) {
        for (var m12 = 0; m12 < a10; m12++)
          f11[m12] = m12;
        var b11 = nt4(f11, l11.slice(), a10, s11), x11 = b11.slice();
        v12(f11, g9);
        var w10 = nt4(f11, b11, s11, 2), E10 = nt4(g9, x11, s11, 2);
        w10.length <= E10.length && w10.length < d12 ? (d12 = w10.length, h10 = w10, v12(f11, p10)) : E10.length <= w10.length && E10.length < d12 && (d12 = E10.length, h10 = E10, v12(g9, p10));
      }
      for (var k10 = this.spawn(h10.map(function(e23) {
        return r10[e23[0]];
      })), C9 = this.spawn(), S8 = this.spawn(), D7 = p10[0], P10 = 0; P10 < p10.length; P10++) {
        var T9 = p10[P10], M9 = n13[P10];
        T9 === D7 ? C9.merge(M9) : S8.merge(M9);
      }
      var B8 = function(t18) {
        var n14 = e22.spawn();
        return t18.forEach(function(t19) {
          n14.merge(t19), t19.connectedEdges().forEach(function(t20) {
            e22.contains(t20) && !k10.contains(t20) && n14.merge(t20);
          });
        }), n14;
      }, _7 = [B8(C9), B8(S8)];
      return { cut: k10, components: _7, partition1: C9, partition2: S8 };
    }
    Pe("At least 2 nodes are required for Karger-Stein algorithm");
  } };
  var at4 = function(e22, t17, n13) {
    return { x: e22.x * t17 + n13.x, y: e22.y * t17 + n13.y };
  };
  var it4 = function(e22, t17, n13) {
    return { x: (e22.x - n13.x) / t17, y: (e22.y - n13.y) / t17 };
  };
  var ot4 = function(e22) {
    return { x: e22[0], y: e22[1] };
  };
  var st4 = function(e22, t17) {
    return Math.atan2(t17, e22) - Math.PI / 2;
  };
  var lt4 = Math.log2 || function(e22) {
    return Math.log(e22) / Math.log(2);
  };
  var ut4 = function(e22) {
    return e22 > 0 ? 1 : e22 < 0 ? -1 : 0;
  };
  var ct4 = function(e22, t17) {
    return Math.sqrt(dt4(e22, t17));
  };
  var dt4 = function(e22, t17) {
    var n13 = t17.x - e22.x, r10 = t17.y - e22.y;
    return n13 * n13 + r10 * r10;
  };
  var ht4 = function(e22) {
    for (var t17 = e22.length, n13 = 0, r10 = 0; r10 < t17; r10++)
      n13 += e22[r10];
    for (var a10 = 0; a10 < t17; a10++)
      e22[a10] = e22[a10] / n13;
    return e22;
  };
  var pt4 = function(e22, t17, n13, r10) {
    return (1 - r10) * (1 - r10) * e22 + 2 * (1 - r10) * r10 * t17 + r10 * r10 * n13;
  };
  var ft4 = function(e22, t17, n13, r10) {
    return { x: pt4(e22.x, t17.x, n13.x, r10), y: pt4(e22.y, t17.y, n13.y, r10) };
  };
  var gt4 = function(e22, t17, n13) {
    return Math.max(e22, Math.min(n13, t17));
  };
  var vt4 = function(e22) {
    if (null == e22)
      return { x1: 1 / 0, y1: 1 / 0, x2: -1 / 0, y2: -1 / 0, w: 0, h: 0 };
    if (null != e22.x1 && null != e22.y1) {
      if (null != e22.x2 && null != e22.y2 && e22.x2 >= e22.x1 && e22.y2 >= e22.y1)
        return { x1: e22.x1, y1: e22.y1, x2: e22.x2, y2: e22.y2, w: e22.x2 - e22.x1, h: e22.y2 - e22.y1 };
      if (null != e22.w && null != e22.h && e22.w >= 0 && e22.h >= 0)
        return { x1: e22.x1, y1: e22.y1, x2: e22.x1 + e22.w, y2: e22.y1 + e22.h, w: e22.w, h: e22.h };
    }
  };
  var yt4 = function(e22, t17, n13) {
    e22.x1 = Math.min(e22.x1, t17), e22.x2 = Math.max(e22.x2, t17), e22.w = e22.x2 - e22.x1, e22.y1 = Math.min(e22.y1, n13), e22.y2 = Math.max(e22.y2, n13), e22.h = e22.y2 - e22.y1;
  };
  var mt4 = function(e22) {
    var t17 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : 0;
    return e22.x1 -= t17, e22.x2 += t17, e22.y1 -= t17, e22.y2 += t17, e22.w = e22.x2 - e22.x1, e22.h = e22.y2 - e22.y1, e22;
  };
  var bt4 = function(e22) {
    var t17, n13, r10, a10, i11 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : [0];
    if (1 === i11.length)
      t17 = n13 = r10 = a10 = i11[0];
    else if (2 === i11.length)
      t17 = r10 = i11[0], a10 = n13 = i11[1];
    else if (4 === i11.length) {
      var o13 = x6(i11, 4);
      t17 = o13[0], n13 = o13[1], r10 = o13[2], a10 = o13[3];
    }
    return e22.x1 -= a10, e22.x2 += n13, e22.y1 -= t17, e22.y2 += r10, e22.w = e22.x2 - e22.x1, e22.h = e22.y2 - e22.y1, e22;
  };
  var xt4 = function(e22, t17) {
    e22.x1 = t17.x1, e22.y1 = t17.y1, e22.x2 = t17.x2, e22.y2 = t17.y2, e22.w = e22.x2 - e22.x1, e22.h = e22.y2 - e22.y1;
  };
  var wt4 = function(e22, t17) {
    return !(e22.x1 > t17.x2) && (!(t17.x1 > e22.x2) && (!(e22.x2 < t17.x1) && (!(t17.x2 < e22.x1) && (!(e22.y2 < t17.y1) && (!(t17.y2 < e22.y1) && (!(e22.y1 > t17.y2) && !(t17.y1 > e22.y2)))))));
  };
  var Et4 = function(e22, t17, n13) {
    return e22.x1 <= t17 && t17 <= e22.x2 && e22.y1 <= n13 && n13 <= e22.y2;
  };
  var kt4 = function(e22, t17) {
    return Et4(e22, t17.x1, t17.y1) && Et4(e22, t17.x2, t17.y2);
  };
  var Ct4 = function(e22, t17, n13, r10, a10, i11, o13) {
    var s11, l11 = jt4(a10, i11), u10 = a10 / 2, c10 = i11 / 2, d12 = r10 - c10 - o13;
    if ((s11 = At4(e22, t17, n13, r10, n13 - u10 + l11 - o13, d12, n13 + u10 - l11 + o13, d12, false)).length > 0)
      return s11;
    var h10 = n13 + u10 + o13;
    if ((s11 = At4(e22, t17, n13, r10, h10, r10 - c10 + l11 - o13, h10, r10 + c10 - l11 + o13, false)).length > 0)
      return s11;
    var p10 = r10 + c10 + o13;
    if ((s11 = At4(e22, t17, n13, r10, n13 - u10 + l11 - o13, p10, n13 + u10 - l11 + o13, p10, false)).length > 0)
      return s11;
    var f11, g9 = n13 - u10 - o13;
    if ((s11 = At4(e22, t17, n13, r10, g9, r10 - c10 + l11 - o13, g9, r10 + c10 - l11 + o13, false)).length > 0)
      return s11;
    var v12 = n13 - u10 + l11, y10 = r10 - c10 + l11;
    if ((f11 = zt4(e22, t17, n13, r10, v12, y10, l11 + o13)).length > 0 && f11[0] <= v12 && f11[1] <= y10)
      return [f11[0], f11[1]];
    var m12 = n13 + u10 - l11, b11 = r10 - c10 + l11;
    if ((f11 = zt4(e22, t17, n13, r10, m12, b11, l11 + o13)).length > 0 && f11[0] >= m12 && f11[1] <= b11)
      return [f11[0], f11[1]];
    var x11 = n13 + u10 - l11, w10 = r10 + c10 - l11;
    if ((f11 = zt4(e22, t17, n13, r10, x11, w10, l11 + o13)).length > 0 && f11[0] >= x11 && f11[1] >= w10)
      return [f11[0], f11[1]];
    var E10 = n13 - u10 + l11, k10 = r10 + c10 - l11;
    return (f11 = zt4(e22, t17, n13, r10, E10, k10, l11 + o13)).length > 0 && f11[0] <= E10 && f11[1] >= k10 ? [f11[0], f11[1]] : [];
  };
  var St4 = function(e22, t17, n13, r10, a10, i11, o13) {
    var s11 = o13, l11 = Math.min(n13, a10), u10 = Math.max(n13, a10), c10 = Math.min(r10, i11), d12 = Math.max(r10, i11);
    return l11 - s11 <= e22 && e22 <= u10 + s11 && c10 - s11 <= t17 && t17 <= d12 + s11;
  };
  var Dt4 = function(e22, t17, n13, r10, a10, i11, o13, s11, l11) {
    var u10 = Math.min(n13, o13, a10) - l11, c10 = Math.max(n13, o13, a10) + l11, d12 = Math.min(r10, s11, i11) - l11, h10 = Math.max(r10, s11, i11) + l11;
    return !(e22 < u10 || e22 > c10 || t17 < d12 || t17 > h10);
  };
  var Pt4 = function(e22, t17, n13, r10, a10, i11, o13, s11) {
    var l11 = [];
    !function(e23, t18, n14, r11, a11) {
      var i12, o14, s12, l12, u11, c11, d13, h11;
      0 === e23 && (e23 = 1e-5), s12 = -27 * (r11 /= e23) + (t18 /= e23) * (9 * (n14 /= e23) - t18 * t18 * 2), i12 = (o14 = (3 * n14 - t18 * t18) / 9) * o14 * o14 + (s12 /= 54) * s12, a11[1] = 0, d13 = t18 / 3, i12 > 0 ? (u11 = (u11 = s12 + Math.sqrt(i12)) < 0 ? -Math.pow(-u11, 1 / 3) : Math.pow(u11, 1 / 3), c11 = (c11 = s12 - Math.sqrt(i12)) < 0 ? -Math.pow(-c11, 1 / 3) : Math.pow(c11, 1 / 3), a11[0] = -d13 + u11 + c11, d13 += (u11 + c11) / 2, a11[4] = a11[2] = -d13, d13 = Math.sqrt(3) * (-c11 + u11) / 2, a11[3] = d13, a11[5] = -d13) : (a11[5] = a11[3] = 0, 0 === i12 ? (h11 = s12 < 0 ? -Math.pow(-s12, 1 / 3) : Math.pow(s12, 1 / 3), a11[0] = 2 * h11 - d13, a11[4] = a11[2] = -(h11 + d13)) : (l12 = (o14 = -o14) * o14 * o14, l12 = Math.acos(s12 / Math.sqrt(l12)), h11 = 2 * Math.sqrt(o14), a11[0] = -d13 + h11 * Math.cos(l12 / 3), a11[2] = -d13 + h11 * Math.cos((l12 + 2 * Math.PI) / 3), a11[4] = -d13 + h11 * Math.cos((l12 + 4 * Math.PI) / 3)));
    }(1 * n13 * n13 - 4 * n13 * a10 + 2 * n13 * o13 + 4 * a10 * a10 - 4 * a10 * o13 + o13 * o13 + r10 * r10 - 4 * r10 * i11 + 2 * r10 * s11 + 4 * i11 * i11 - 4 * i11 * s11 + s11 * s11, 9 * n13 * a10 - 3 * n13 * n13 - 3 * n13 * o13 - 6 * a10 * a10 + 3 * a10 * o13 + 9 * r10 * i11 - 3 * r10 * r10 - 3 * r10 * s11 - 6 * i11 * i11 + 3 * i11 * s11, 3 * n13 * n13 - 6 * n13 * a10 + n13 * o13 - n13 * e22 + 2 * a10 * a10 + 2 * a10 * e22 - o13 * e22 + 3 * r10 * r10 - 6 * r10 * i11 + r10 * s11 - r10 * t17 + 2 * i11 * i11 + 2 * i11 * t17 - s11 * t17, 1 * n13 * a10 - n13 * n13 + n13 * e22 - a10 * e22 + r10 * i11 - r10 * r10 + r10 * t17 - i11 * t17, l11);
    for (var u10 = [], c10 = 0; c10 < 6; c10 += 2)
      Math.abs(l11[c10 + 1]) < 1e-7 && l11[c10] >= 0 && l11[c10] <= 1 && u10.push(l11[c10]);
    u10.push(1), u10.push(0);
    for (var d12, h10, p10, f11 = -1, g9 = 0; g9 < u10.length; g9++)
      d12 = Math.pow(1 - u10[g9], 2) * n13 + 2 * (1 - u10[g9]) * u10[g9] * a10 + u10[g9] * u10[g9] * o13, h10 = Math.pow(1 - u10[g9], 2) * r10 + 2 * (1 - u10[g9]) * u10[g9] * i11 + u10[g9] * u10[g9] * s11, p10 = Math.pow(d12 - e22, 2) + Math.pow(h10 - t17, 2), f11 >= 0 ? p10 < f11 && (f11 = p10) : f11 = p10;
    return f11;
  };
  var Tt4 = function(e22, t17, n13, r10, a10, i11) {
    var o13 = [e22 - n13, t17 - r10], s11 = [a10 - n13, i11 - r10], l11 = s11[0] * s11[0] + s11[1] * s11[1], u10 = o13[0] * o13[0] + o13[1] * o13[1], c10 = o13[0] * s11[0] + o13[1] * s11[1], d12 = c10 * c10 / l11;
    return c10 < 0 ? u10 : d12 > l11 ? (e22 - a10) * (e22 - a10) + (t17 - i11) * (t17 - i11) : u10 - d12;
  };
  var Mt4 = function(e22, t17, n13) {
    for (var r10, a10, i11, o13, s11 = 0, l11 = 0; l11 < n13.length / 2; l11++)
      if (r10 = n13[2 * l11], a10 = n13[2 * l11 + 1], l11 + 1 < n13.length / 2 ? (i11 = n13[2 * (l11 + 1)], o13 = n13[2 * (l11 + 1) + 1]) : (i11 = n13[2 * (l11 + 1 - n13.length / 2)], o13 = n13[2 * (l11 + 1 - n13.length / 2) + 1]), r10 == e22 && i11 == e22)
        ;
      else {
        if (!(r10 >= e22 && e22 >= i11 || r10 <= e22 && e22 <= i11))
          continue;
        (e22 - r10) / (i11 - r10) * (o13 - a10) + a10 > t17 && s11++;
      }
    return s11 % 2 != 0;
  };
  var Bt4 = function(e22, t17, n13, r10, a10, i11, o13, s11, l11) {
    var u10, c10 = new Array(n13.length);
    null != s11[0] ? (u10 = Math.atan(s11[1] / s11[0]), s11[0] < 0 ? u10 += Math.PI / 2 : u10 = -u10 - Math.PI / 2) : u10 = s11;
    for (var d12, h10 = Math.cos(-u10), p10 = Math.sin(-u10), f11 = 0; f11 < c10.length / 2; f11++)
      c10[2 * f11] = i11 / 2 * (n13[2 * f11] * h10 - n13[2 * f11 + 1] * p10), c10[2 * f11 + 1] = o13 / 2 * (n13[2 * f11 + 1] * h10 + n13[2 * f11] * p10), c10[2 * f11] += r10, c10[2 * f11 + 1] += a10;
    if (l11 > 0) {
      var g9 = Nt4(c10, -l11);
      d12 = _t4(g9);
    } else
      d12 = c10;
    return Mt4(e22, t17, d12);
  };
  var _t4 = function(e22) {
    for (var t17, n13, r10, a10, i11, o13, s11, l11, u10 = new Array(e22.length / 2), c10 = 0; c10 < e22.length / 4; c10++) {
      t17 = e22[4 * c10], n13 = e22[4 * c10 + 1], r10 = e22[4 * c10 + 2], a10 = e22[4 * c10 + 3], c10 < e22.length / 4 - 1 ? (i11 = e22[4 * (c10 + 1)], o13 = e22[4 * (c10 + 1) + 1], s11 = e22[4 * (c10 + 1) + 2], l11 = e22[4 * (c10 + 1) + 3]) : (i11 = e22[0], o13 = e22[1], s11 = e22[2], l11 = e22[3]);
      var d12 = At4(t17, n13, r10, a10, i11, o13, s11, l11, true);
      u10[2 * c10] = d12[0], u10[2 * c10 + 1] = d12[1];
    }
    return u10;
  };
  var Nt4 = function(e22, t17) {
    for (var n13, r10, a10, i11, o13 = new Array(2 * e22.length), s11 = 0; s11 < e22.length / 2; s11++) {
      n13 = e22[2 * s11], r10 = e22[2 * s11 + 1], s11 < e22.length / 2 - 1 ? (a10 = e22[2 * (s11 + 1)], i11 = e22[2 * (s11 + 1) + 1]) : (a10 = e22[0], i11 = e22[1]);
      var l11 = i11 - r10, u10 = -(a10 - n13), c10 = Math.sqrt(l11 * l11 + u10 * u10), d12 = l11 / c10, h10 = u10 / c10;
      o13[4 * s11] = n13 + d12 * t17, o13[4 * s11 + 1] = r10 + h10 * t17, o13[4 * s11 + 2] = a10 + d12 * t17, o13[4 * s11 + 3] = i11 + h10 * t17;
    }
    return o13;
  };
  var It4 = function(e22, t17, n13, r10, a10, i11, o13) {
    return e22 -= a10, t17 -= i11, (e22 /= n13 / 2 + o13) * e22 + (t17 /= r10 / 2 + o13) * t17 <= 1;
  };
  var zt4 = function(e22, t17, n13, r10, a10, i11, o13) {
    var s11 = [n13 - e22, r10 - t17], l11 = [e22 - a10, t17 - i11], u10 = s11[0] * s11[0] + s11[1] * s11[1], c10 = 2 * (l11[0] * s11[0] + l11[1] * s11[1]), d12 = c10 * c10 - 4 * u10 * (l11[0] * l11[0] + l11[1] * l11[1] - o13 * o13);
    if (d12 < 0)
      return [];
    var h10 = (-c10 + Math.sqrt(d12)) / (2 * u10), p10 = (-c10 - Math.sqrt(d12)) / (2 * u10), f11 = Math.min(h10, p10), g9 = Math.max(h10, p10), v12 = [];
    if (f11 >= 0 && f11 <= 1 && v12.push(f11), g9 >= 0 && g9 <= 1 && v12.push(g9), 0 === v12.length)
      return [];
    var y10 = v12[0] * s11[0] + e22, m12 = v12[0] * s11[1] + t17;
    return v12.length > 1 ? v12[0] == v12[1] ? [y10, m12] : [y10, m12, v12[1] * s11[0] + e22, v12[1] * s11[1] + t17] : [y10, m12];
  };
  var Lt4 = function(e22, t17, n13) {
    return t17 <= e22 && e22 <= n13 || n13 <= e22 && e22 <= t17 ? e22 : e22 <= t17 && t17 <= n13 || n13 <= t17 && t17 <= e22 ? t17 : n13;
  };
  var At4 = function(e22, t17, n13, r10, a10, i11, o13, s11, l11) {
    var u10 = e22 - a10, c10 = n13 - e22, d12 = o13 - a10, h10 = t17 - i11, p10 = r10 - t17, f11 = s11 - i11, g9 = d12 * h10 - f11 * u10, v12 = c10 * h10 - p10 * u10, y10 = f11 * c10 - d12 * p10;
    if (0 !== y10) {
      var m12 = g9 / y10, b11 = v12 / y10, x11 = -1e-3;
      return x11 <= m12 && m12 <= 1.001 && x11 <= b11 && b11 <= 1.001 || l11 ? [e22 + m12 * c10, t17 + m12 * p10] : [];
    }
    return 0 === g9 || 0 === v12 ? Lt4(e22, n13, o13) === o13 ? [o13, s11] : Lt4(e22, n13, a10) === a10 ? [a10, i11] : Lt4(a10, o13, n13) === n13 ? [n13, r10] : [] : [];
  };
  var Ot4 = function(e22, t17, n13, r10, a10, i11, o13, s11) {
    var l11, u10, c10, d12, h10, p10, f11 = [], g9 = new Array(n13.length), v12 = true;
    if (null == i11 && (v12 = false), v12) {
      for (var y10 = 0; y10 < g9.length / 2; y10++)
        g9[2 * y10] = n13[2 * y10] * i11 + r10, g9[2 * y10 + 1] = n13[2 * y10 + 1] * o13 + a10;
      if (s11 > 0) {
        var m12 = Nt4(g9, -s11);
        u10 = _t4(m12);
      } else
        u10 = g9;
    } else
      u10 = n13;
    for (var b11 = 0; b11 < u10.length / 2; b11++)
      c10 = u10[2 * b11], d12 = u10[2 * b11 + 1], b11 < u10.length / 2 - 1 ? (h10 = u10[2 * (b11 + 1)], p10 = u10[2 * (b11 + 1) + 1]) : (h10 = u10[0], p10 = u10[1]), 0 !== (l11 = At4(e22, t17, r10, a10, c10, d12, h10, p10)).length && f11.push(l11[0], l11[1]);
    return f11;
  };
  var Rt4 = function(e22, t17, n13) {
    var r10 = [e22[0] - t17[0], e22[1] - t17[1]], a10 = Math.sqrt(r10[0] * r10[0] + r10[1] * r10[1]), i11 = (a10 - n13) / a10;
    return i11 < 0 && (i11 = 1e-5), [t17[0] + i11 * r10[0], t17[1] + i11 * r10[1]];
  };
  var Vt4 = function(e22, t17) {
    var n13 = qt4(e22, t17);
    return n13 = Ft4(n13);
  };
  var Ft4 = function(e22) {
    for (var t17, n13, r10 = e22.length / 2, a10 = 1 / 0, i11 = 1 / 0, o13 = -1 / 0, s11 = -1 / 0, l11 = 0; l11 < r10; l11++)
      t17 = e22[2 * l11], n13 = e22[2 * l11 + 1], a10 = Math.min(a10, t17), o13 = Math.max(o13, t17), i11 = Math.min(i11, n13), s11 = Math.max(s11, n13);
    for (var u10 = 2 / (o13 - a10), c10 = 2 / (s11 - i11), d12 = 0; d12 < r10; d12++)
      t17 = e22[2 * d12] = e22[2 * d12] * u10, n13 = e22[2 * d12 + 1] = e22[2 * d12 + 1] * c10, a10 = Math.min(a10, t17), o13 = Math.max(o13, t17), i11 = Math.min(i11, n13), s11 = Math.max(s11, n13);
    if (i11 < -1)
      for (var h10 = 0; h10 < r10; h10++)
        n13 = e22[2 * h10 + 1] = e22[2 * h10 + 1] + (-1 - i11);
    return e22;
  };
  var qt4 = function(e22, t17) {
    var n13 = 1 / e22 * 2 * Math.PI, r10 = e22 % 2 == 0 ? Math.PI / 2 + n13 / 2 : Math.PI / 2;
    r10 += t17;
    for (var a10, i11 = new Array(2 * e22), o13 = 0; o13 < e22; o13++)
      a10 = o13 * n13 + r10, i11[2 * o13] = Math.cos(a10), i11[2 * o13 + 1] = Math.sin(-a10);
    return i11;
  };
  var jt4 = function(e22, t17) {
    return Math.min(e22 / 4, t17 / 4, 8);
  };
  var Yt4 = function(e22, t17) {
    return Math.min(e22 / 10, t17 / 10, 8);
  };
  var Xt4 = function(e22, t17) {
    return { heightOffset: Math.min(15, 0.05 * t17), widthOffset: Math.min(100, 0.25 * e22), ctrlPtOffsetPct: 0.05 };
  };
  var Wt4 = ze({ dampingFactor: 0.8, precision: 1e-6, iterations: 200, weight: function(e22) {
    return 1;
  } });
  var Ht4 = { pageRank: function(e22) {
    for (var t17 = Wt4(e22), n13 = t17.dampingFactor, r10 = t17.precision, a10 = t17.iterations, i11 = t17.weight, o13 = this._private.cy, s11 = this.byGroup(), l11 = s11.nodes, u10 = s11.edges, c10 = l11.length, d12 = c10 * c10, h10 = u10.length, p10 = new Array(d12), f11 = new Array(c10), g9 = (1 - n13) / c10, v12 = 0; v12 < c10; v12++) {
      for (var y10 = 0; y10 < c10; y10++) {
        p10[v12 * c10 + y10] = 0;
      }
      f11[v12] = 0;
    }
    for (var m12 = 0; m12 < h10; m12++) {
      var b11 = u10[m12], x11 = b11.data("source"), w10 = b11.data("target");
      if (x11 !== w10) {
        var E10 = l11.indexOfId(x11), k10 = l11.indexOfId(w10), C9 = i11(b11);
        p10[k10 * c10 + E10] += C9, f11[E10] += C9;
      }
    }
    for (var S8 = 1 / c10 + g9, D7 = 0; D7 < c10; D7++)
      if (0 === f11[D7])
        for (var P10 = 0; P10 < c10; P10++) {
          p10[P10 * c10 + D7] = S8;
        }
      else
        for (var T9 = 0; T9 < c10; T9++) {
          var M9 = T9 * c10 + D7;
          p10[M9] = p10[M9] / f11[D7] + g9;
        }
    for (var B8, _7 = new Array(c10), N8 = new Array(c10), I8 = 0; I8 < c10; I8++)
      _7[I8] = 1;
    for (var z8 = 0; z8 < a10; z8++) {
      for (var L10 = 0; L10 < c10; L10++)
        N8[L10] = 0;
      for (var A10 = 0; A10 < c10; A10++)
        for (var O9 = 0; O9 < c10; O9++) {
          var R8 = A10 * c10 + O9;
          N8[A10] += p10[R8] * _7[O9];
        }
      ht4(N8), B8 = _7, _7 = N8, N8 = B8;
      for (var V8 = 0, F9 = 0; F9 < c10; F9++) {
        var q8 = B8[F9] - _7[F9];
        V8 += q8 * q8;
      }
      if (V8 < r10)
        break;
    }
    return { rank: function(e23) {
      return e23 = o13.collection(e23)[0], _7[l11.indexOf(e23)];
    } };
  } };
  var Kt4 = ze({ root: null, weight: function(e22) {
    return 1;
  }, directed: false, alpha: 0 });
  var Gt4 = { degreeCentralityNormalized: function(e22) {
    e22 = Kt4(e22);
    var t17 = this.cy(), n13 = this.nodes(), r10 = n13.length;
    if (e22.directed) {
      for (var a10 = {}, i11 = {}, o13 = 0, s11 = 0, l11 = 0; l11 < r10; l11++) {
        var u10 = n13[l11], c10 = u10.id();
        e22.root = u10;
        var d12 = this.degreeCentrality(e22);
        o13 < d12.indegree && (o13 = d12.indegree), s11 < d12.outdegree && (s11 = d12.outdegree), a10[c10] = d12.indegree, i11[c10] = d12.outdegree;
      }
      return { indegree: function(e23) {
        return 0 == o13 ? 0 : (M6(e23) && (e23 = t17.filter(e23)), a10[e23.id()] / o13);
      }, outdegree: function(e23) {
        return 0 === s11 ? 0 : (M6(e23) && (e23 = t17.filter(e23)), i11[e23.id()] / s11);
      } };
    }
    for (var h10 = {}, p10 = 0, f11 = 0; f11 < r10; f11++) {
      var g9 = n13[f11];
      e22.root = g9;
      var v12 = this.degreeCentrality(e22);
      p10 < v12.degree && (p10 = v12.degree), h10[g9.id()] = v12.degree;
    }
    return { degree: function(e23) {
      return 0 === p10 ? 0 : (M6(e23) && (e23 = t17.filter(e23)), h10[e23.id()] / p10);
    } };
  }, degreeCentrality: function(e22) {
    e22 = Kt4(e22);
    var t17 = this.cy(), n13 = this, r10 = e22, a10 = r10.root, i11 = r10.weight, o13 = r10.directed, s11 = r10.alpha;
    if (a10 = t17.collection(a10)[0], o13) {
      for (var l11 = a10.connectedEdges(), u10 = l11.filter(function(e23) {
        return e23.target().same(a10) && n13.has(e23);
      }), c10 = l11.filter(function(e23) {
        return e23.source().same(a10) && n13.has(e23);
      }), d12 = u10.length, h10 = c10.length, p10 = 0, f11 = 0, g9 = 0; g9 < u10.length; g9++)
        p10 += i11(u10[g9]);
      for (var v12 = 0; v12 < c10.length; v12++)
        f11 += i11(c10[v12]);
      return { indegree: Math.pow(d12, 1 - s11) * Math.pow(p10, s11), outdegree: Math.pow(h10, 1 - s11) * Math.pow(f11, s11) };
    }
    for (var y10 = a10.connectedEdges().intersection(n13), m12 = y10.length, b11 = 0, x11 = 0; x11 < y10.length; x11++)
      b11 += i11(y10[x11]);
    return { degree: Math.pow(m12, 1 - s11) * Math.pow(b11, s11) };
  } };
  Gt4.dc = Gt4.degreeCentrality, Gt4.dcn = Gt4.degreeCentralityNormalised = Gt4.degreeCentralityNormalized;
  var Ut4 = ze({ harmonic: true, weight: function() {
    return 1;
  }, directed: false, root: null });
  var Zt4 = { closenessCentralityNormalized: function(e22) {
    for (var t17 = Ut4(e22), n13 = t17.harmonic, r10 = t17.weight, a10 = t17.directed, i11 = this.cy(), o13 = {}, s11 = 0, l11 = this.nodes(), u10 = this.floydWarshall({ weight: r10, directed: a10 }), c10 = 0; c10 < l11.length; c10++) {
      for (var d12 = 0, h10 = l11[c10], p10 = 0; p10 < l11.length; p10++)
        if (c10 !== p10) {
          var f11 = u10.distance(h10, l11[p10]);
          d12 += n13 ? 1 / f11 : f11;
        }
      n13 || (d12 = 1 / d12), s11 < d12 && (s11 = d12), o13[h10.id()] = d12;
    }
    return { closeness: function(e23) {
      return 0 == s11 ? 0 : (e23 = M6(e23) ? i11.filter(e23)[0].id() : e23.id(), o13[e23] / s11);
    } };
  }, closenessCentrality: function(e22) {
    var t17 = Ut4(e22), n13 = t17.root, r10 = t17.weight, a10 = t17.directed, i11 = t17.harmonic;
    n13 = this.filter(n13)[0];
    for (var o13 = this.dijkstra({ root: n13, weight: r10, directed: a10 }), s11 = 0, l11 = this.nodes(), u10 = 0; u10 < l11.length; u10++) {
      var c10 = l11[u10];
      if (!c10.same(n13)) {
        var d12 = o13.distanceTo(c10);
        s11 += i11 ? 1 / d12 : d12;
      }
    }
    return i11 ? s11 : 1 / s11;
  } };
  Zt4.cc = Zt4.closenessCentrality, Zt4.ccn = Zt4.closenessCentralityNormalised = Zt4.closenessCentralityNormalized;
  var $t4 = ze({ weight: null, directed: false });
  var Qt4 = { betweennessCentrality: function(e22) {
    for (var t17 = $t4(e22), n13 = t17.directed, r10 = t17.weight, a10 = null != r10, i11 = this.cy(), o13 = this.nodes(), s11 = {}, l11 = {}, u10 = 0, c10 = function(e23, t18) {
      l11[e23] = t18, t18 > u10 && (u10 = t18);
    }, h10 = function(e23) {
      return l11[e23];
    }, p10 = 0; p10 < o13.length; p10++) {
      var f11 = o13[p10], g9 = f11.id();
      s11[g9] = n13 ? f11.outgoers().nodes() : f11.openNeighborhood().nodes(), c10(g9, 0);
    }
    for (var v12 = function(e23) {
      for (var t18 = o13[e23].id(), n14 = [], l12 = {}, u11 = {}, p11 = {}, f12 = new d7.default(function(e24, t19) {
        return p11[e24] - p11[t19];
      }), g10 = 0; g10 < o13.length; g10++) {
        var v13 = o13[g10].id();
        l12[v13] = [], u11[v13] = 0, p11[v13] = 1 / 0;
      }
      for (u11[t18] = 1, p11[t18] = 0, f12.push(t18); !f12.empty(); ) {
        var y11 = f12.pop();
        if (n14.push(y11), a10)
          for (var m13 = 0; m13 < s11[y11].length; m13++) {
            var b11 = s11[y11][m13], x11 = i11.getElementById(y11), w10 = void 0;
            w10 = x11.edgesTo(b11).length > 0 ? x11.edgesTo(b11)[0] : b11.edgesTo(x11)[0];
            var E10 = r10(w10);
            b11 = b11.id(), p11[b11] > p11[y11] + E10 && (p11[b11] = p11[y11] + E10, f12.nodes.indexOf(b11) < 0 ? f12.push(b11) : f12.updateItem(b11), u11[b11] = 0, l12[b11] = []), p11[b11] == p11[y11] + E10 && (u11[b11] = u11[b11] + u11[y11], l12[b11].push(y11));
          }
        else
          for (var k10 = 0; k10 < s11[y11].length; k10++) {
            var C9 = s11[y11][k10].id();
            p11[C9] == 1 / 0 && (f12.push(C9), p11[C9] = p11[y11] + 1), p11[C9] == p11[y11] + 1 && (u11[C9] = u11[C9] + u11[y11], l12[C9].push(y11));
          }
      }
      for (var S8 = {}, D7 = 0; D7 < o13.length; D7++)
        S8[o13[D7].id()] = 0;
      for (; n14.length > 0; ) {
        for (var P10 = n14.pop(), T9 = 0; T9 < l12[P10].length; T9++) {
          var M9 = l12[P10][T9];
          S8[M9] = S8[M9] + u11[M9] / u11[P10] * (1 + S8[P10]);
        }
        P10 != o13[e23].id() && c10(P10, h10(P10) + S8[P10]);
      }
    }, y10 = 0; y10 < o13.length; y10++)
      v12(y10);
    var m12 = { betweenness: function(e23) {
      var t18 = i11.collection(e23).id();
      return h10(t18);
    }, betweennessNormalized: function(e23) {
      if (0 == u10)
        return 0;
      var t18 = i11.collection(e23).id();
      return h10(t18) / u10;
    } };
    return m12.betweennessNormalised = m12.betweennessNormalized, m12;
  } };
  Qt4.bc = Qt4.betweennessCentrality;
  var Jt4 = ze({ expandFactor: 2, inflateFactor: 2, multFactor: 1, maxIterations: 20, attributes: [function(e22) {
    return 1;
  }] });
  var en = function(e22, t17) {
    for (var n13 = 0, r10 = 0; r10 < t17.length; r10++)
      n13 += t17[r10](e22);
    return n13;
  };
  var tn = function(e22, t17) {
    for (var n13, r10 = 0; r10 < t17; r10++) {
      n13 = 0;
      for (var a10 = 0; a10 < t17; a10++)
        n13 += e22[a10 * t17 + r10];
      for (var i11 = 0; i11 < t17; i11++)
        e22[i11 * t17 + r10] = e22[i11 * t17 + r10] / n13;
    }
  };
  var nn = function(e22, t17, n13) {
    for (var r10 = new Array(n13 * n13), a10 = 0; a10 < n13; a10++) {
      for (var i11 = 0; i11 < n13; i11++)
        r10[a10 * n13 + i11] = 0;
      for (var o13 = 0; o13 < n13; o13++)
        for (var s11 = 0; s11 < n13; s11++)
          r10[a10 * n13 + s11] += e22[a10 * n13 + o13] * t17[o13 * n13 + s11];
    }
    return r10;
  };
  var rn = function(e22, t17, n13) {
    for (var r10 = e22.slice(0), a10 = 1; a10 < n13; a10++)
      e22 = nn(e22, r10, t17);
    return e22;
  };
  var an = function(e22, t17, n13) {
    for (var r10 = new Array(t17 * t17), a10 = 0; a10 < t17 * t17; a10++)
      r10[a10] = Math.pow(e22[a10], n13);
    return tn(r10, t17), r10;
  };
  var on = function(e22, t17, n13, r10) {
    for (var a10 = 0; a10 < n13; a10++) {
      if (Math.round(e22[a10] * Math.pow(10, r10)) / Math.pow(10, r10) !== Math.round(t17[a10] * Math.pow(10, r10)) / Math.pow(10, r10))
        return false;
    }
    return true;
  };
  var sn = function(e22, t17) {
    for (var n13 = 0; n13 < e22.length; n13++)
      if (!t17[n13] || e22[n13].id() !== t17[n13].id())
        return false;
    return true;
  };
  var ln = function(e22) {
    for (var t17 = this.nodes(), n13 = this.edges(), r10 = this.cy(), a10 = function(e23) {
      return Jt4(e23);
    }(e22), i11 = {}, o13 = 0; o13 < t17.length; o13++)
      i11[t17[o13].id()] = o13;
    for (var s11, l11 = t17.length, u10 = l11 * l11, c10 = new Array(u10), d12 = 0; d12 < u10; d12++)
      c10[d12] = 0;
    for (var h10 = 0; h10 < n13.length; h10++) {
      var p10 = n13[h10], f11 = i11[p10.source().id()], g9 = i11[p10.target().id()], v12 = en(p10, a10.attributes);
      c10[f11 * l11 + g9] += v12, c10[g9 * l11 + f11] += v12;
    }
    !function(e23, t18, n14) {
      for (var r11 = 0; r11 < t18; r11++)
        e23[r11 * t18 + r11] = n14;
    }(c10, l11, a10.multFactor), tn(c10, l11);
    for (var y10 = true, m12 = 0; y10 && m12 < a10.maxIterations; )
      y10 = false, s11 = rn(c10, l11, a10.expandFactor), c10 = an(s11, l11, a10.inflateFactor), on(c10, s11, u10, 4) || (y10 = true), m12++;
    var b11 = function(e23, t18, n14, r11) {
      for (var a11 = [], i12 = 0; i12 < t18; i12++) {
        for (var o14 = [], s12 = 0; s12 < t18; s12++)
          Math.round(1e3 * e23[i12 * t18 + s12]) / 1e3 > 0 && o14.push(n14[s12]);
        0 !== o14.length && a11.push(r11.collection(o14));
      }
      return a11;
    }(c10, l11, t17, r10);
    return b11 = function(e23) {
      for (var t18 = 0; t18 < e23.length; t18++)
        for (var n14 = 0; n14 < e23.length; n14++)
          t18 != n14 && sn(e23[t18], e23[n14]) && e23.splice(n14, 1);
      return e23;
    }(b11), b11;
  };
  var un = { markovClustering: ln, mcl: ln };
  var cn = function(e22) {
    return e22;
  };
  var dn = function(e22, t17) {
    return Math.abs(t17 - e22);
  };
  var hn = function(e22, t17, n13) {
    return e22 + dn(t17, n13);
  };
  var pn = function(e22, t17, n13) {
    return e22 + Math.pow(n13 - t17, 2);
  };
  var fn = function(e22) {
    return Math.sqrt(e22);
  };
  var gn = function(e22, t17, n13) {
    return Math.max(e22, dn(t17, n13));
  };
  var vn = function(e22, t17, n13, r10, a10) {
    for (var i11 = arguments.length > 5 && void 0 !== arguments[5] ? arguments[5] : cn, o13 = r10, s11 = 0; s11 < e22; s11++)
      o13 = a10(o13, t17(s11), n13(s11));
    return i11(o13);
  };
  var yn = { euclidean: function(e22, t17, n13) {
    return e22 >= 2 ? vn(e22, t17, n13, 0, pn, fn) : vn(e22, t17, n13, 0, hn);
  }, squaredEuclidean: function(e22, t17, n13) {
    return vn(e22, t17, n13, 0, pn);
  }, manhattan: function(e22, t17, n13) {
    return vn(e22, t17, n13, 0, hn);
  }, max: function(e22, t17, n13) {
    return vn(e22, t17, n13, -1 / 0, gn);
  } };
  function mn(e22, t17, n13, r10, a10, i11) {
    var o13;
    return o13 = B4(e22) ? e22 : yn[e22] || yn.euclidean, 0 === t17 && B4(e22) ? o13(a10, i11) : o13(t17, n13, r10, a10, i11);
  }
  yn["squared-euclidean"] = yn.squaredEuclidean, yn.squaredeuclidean = yn.squaredEuclidean;
  var bn = ze({ k: 2, m: 2, sensitivityThreshold: 1e-4, distance: "euclidean", maxIterations: 10, attributes: [], testMode: false, testCentroids: null });
  var xn = function(e22) {
    return bn(e22);
  };
  var wn = function(e22, t17, n13, r10, a10) {
    var i11 = "kMedoids" !== a10 ? function(e23) {
      return n13[e23];
    } : function(e23) {
      return r10[e23](n13);
    }, o13 = n13, s11 = t17;
    return mn(e22, r10.length, i11, function(e23) {
      return r10[e23](t17);
    }, o13, s11);
  };
  var En = function(e22, t17, n13) {
    for (var r10 = n13.length, a10 = new Array(r10), i11 = new Array(r10), o13 = new Array(t17), s11 = null, l11 = 0; l11 < r10; l11++)
      a10[l11] = e22.min(n13[l11]).value, i11[l11] = e22.max(n13[l11]).value;
    for (var u10 = 0; u10 < t17; u10++) {
      s11 = [];
      for (var c10 = 0; c10 < r10; c10++)
        s11[c10] = Math.random() * (i11[c10] - a10[c10]) + a10[c10];
      o13[u10] = s11;
    }
    return o13;
  };
  var kn = function(e22, t17, n13, r10, a10) {
    for (var i11 = 1 / 0, o13 = 0, s11 = 0; s11 < t17.length; s11++) {
      var l11 = wn(n13, e22, t17[s11], r10, a10);
      l11 < i11 && (i11 = l11, o13 = s11);
    }
    return o13;
  };
  var Cn = function(e22, t17, n13) {
    for (var r10 = [], a10 = null, i11 = 0; i11 < t17.length; i11++)
      n13[(a10 = t17[i11]).id()] === e22 && r10.push(a10);
    return r10;
  };
  var Sn = function(e22, t17, n13) {
    for (var r10 = 0; r10 < e22.length; r10++)
      for (var a10 = 0; a10 < e22[r10].length; a10++) {
        if (Math.abs(e22[r10][a10] - t17[r10][a10]) > n13)
          return false;
      }
    return true;
  };
  var Dn = function(e22, t17, n13) {
    for (var r10 = 0; r10 < n13; r10++)
      if (e22 === t17[r10])
        return true;
    return false;
  };
  var Pn = function(e22, t17) {
    var n13 = new Array(t17);
    if (e22.length < 50)
      for (var r10 = 0; r10 < t17; r10++) {
        for (var a10 = e22[Math.floor(Math.random() * e22.length)]; Dn(a10, n13, r10); )
          a10 = e22[Math.floor(Math.random() * e22.length)];
        n13[r10] = a10;
      }
    else
      for (var i11 = 0; i11 < t17; i11++)
        n13[i11] = e22[Math.floor(Math.random() * e22.length)];
    return n13;
  };
  var Tn = function(e22, t17, n13) {
    for (var r10 = 0, a10 = 0; a10 < t17.length; a10++)
      r10 += wn("manhattan", t17[a10], e22, n13, "kMedoids");
    return r10;
  };
  var Mn = function(e22, t17, n13, r10, a10) {
    for (var i11, o13, s11 = 0; s11 < t17.length; s11++)
      for (var l11 = 0; l11 < e22.length; l11++)
        r10[s11][l11] = Math.pow(n13[s11][l11], a10.m);
    for (var u10 = 0; u10 < e22.length; u10++)
      for (var c10 = 0; c10 < a10.attributes.length; c10++) {
        i11 = 0, o13 = 0;
        for (var d12 = 0; d12 < t17.length; d12++)
          i11 += r10[d12][u10] * a10.attributes[c10](t17[d12]), o13 += r10[d12][u10];
        e22[u10][c10] = i11 / o13;
      }
  };
  var Bn = function(e22, t17, n13, r10, a10) {
    for (var i11 = 0; i11 < e22.length; i11++)
      t17[i11] = e22[i11].slice();
    for (var o13, s11, l11, u10 = 2 / (a10.m - 1), c10 = 0; c10 < n13.length; c10++)
      for (var d12 = 0; d12 < r10.length; d12++) {
        o13 = 0;
        for (var h10 = 0; h10 < n13.length; h10++)
          s11 = wn(a10.distance, r10[d12], n13[c10], a10.attributes, "cmeans"), l11 = wn(a10.distance, r10[d12], n13[h10], a10.attributes, "cmeans"), o13 += Math.pow(s11 / l11, u10);
        e22[d12][c10] = 1 / o13;
      }
  };
  var _n = function(e22) {
    var t17, n13, r10, a10, i11, o13 = this.cy(), s11 = this.nodes(), l11 = xn(e22);
    a10 = new Array(s11.length);
    for (var u10 = 0; u10 < s11.length; u10++)
      a10[u10] = new Array(l11.k);
    r10 = new Array(s11.length);
    for (var c10 = 0; c10 < s11.length; c10++)
      r10[c10] = new Array(l11.k);
    for (var d12 = 0; d12 < s11.length; d12++) {
      for (var h10 = 0, p10 = 0; p10 < l11.k; p10++)
        r10[d12][p10] = Math.random(), h10 += r10[d12][p10];
      for (var f11 = 0; f11 < l11.k; f11++)
        r10[d12][f11] = r10[d12][f11] / h10;
    }
    n13 = new Array(l11.k);
    for (var g9 = 0; g9 < l11.k; g9++)
      n13[g9] = new Array(l11.attributes.length);
    i11 = new Array(s11.length);
    for (var v12 = 0; v12 < s11.length; v12++)
      i11[v12] = new Array(l11.k);
    for (var y10 = true, m12 = 0; y10 && m12 < l11.maxIterations; )
      y10 = false, Mn(n13, s11, r10, i11, l11), Bn(r10, a10, n13, s11, l11), Sn(r10, a10, l11.sensitivityThreshold) || (y10 = true), m12++;
    return t17 = function(e23, t18, n14, r11) {
      for (var a11, i12, o14 = new Array(n14.k), s12 = 0; s12 < o14.length; s12++)
        o14[s12] = [];
      for (var l12 = 0; l12 < t18.length; l12++) {
        a11 = -1 / 0, i12 = -1;
        for (var u11 = 0; u11 < t18[0].length; u11++)
          t18[l12][u11] > a11 && (a11 = t18[l12][u11], i12 = u11);
        o14[i12].push(e23[l12]);
      }
      for (var c11 = 0; c11 < o14.length; c11++)
        o14[c11] = r11.collection(o14[c11]);
      return o14;
    }(s11, r10, l11, o13), { clusters: t17, degreeOfMembership: r10 };
  };
  var Nn = { kMeans: function(e22) {
    var t17, n13 = this.cy(), r10 = this.nodes(), a10 = null, i11 = xn(e22), o13 = new Array(i11.k), s11 = {};
    i11.testMode ? "number" == typeof i11.testCentroids ? (i11.testCentroids, t17 = En(r10, i11.k, i11.attributes)) : t17 = "object" === g6(i11.testCentroids) ? i11.testCentroids : En(r10, i11.k, i11.attributes) : t17 = En(r10, i11.k, i11.attributes);
    for (var l11, u10, c10, d12 = true, h10 = 0; d12 && h10 < i11.maxIterations; ) {
      for (var p10 = 0; p10 < r10.length; p10++)
        s11[(a10 = r10[p10]).id()] = kn(a10, t17, i11.distance, i11.attributes, "kMeans");
      d12 = false;
      for (var f11 = 0; f11 < i11.k; f11++) {
        var v12 = Cn(f11, r10, s11);
        if (0 !== v12.length) {
          for (var y10 = i11.attributes.length, m12 = t17[f11], b11 = new Array(y10), x11 = new Array(y10), w10 = 0; w10 < y10; w10++) {
            x11[w10] = 0;
            for (var E10 = 0; E10 < v12.length; E10++)
              a10 = v12[E10], x11[w10] += i11.attributes[w10](a10);
            b11[w10] = x11[w10] / v12.length, l11 = b11[w10], u10 = m12[w10], c10 = i11.sensitivityThreshold, Math.abs(u10 - l11) <= c10 || (d12 = true);
          }
          t17[f11] = b11, o13[f11] = n13.collection(v12);
        }
      }
      h10++;
    }
    return o13;
  }, kMedoids: function(e22) {
    var t17, n13, r10 = this.cy(), a10 = this.nodes(), i11 = null, o13 = xn(e22), s11 = new Array(o13.k), l11 = {}, u10 = new Array(o13.k);
    o13.testMode ? "number" == typeof o13.testCentroids || (t17 = "object" === g6(o13.testCentroids) ? o13.testCentroids : Pn(a10, o13.k)) : t17 = Pn(a10, o13.k);
    for (var c10 = true, d12 = 0; c10 && d12 < o13.maxIterations; ) {
      for (var h10 = 0; h10 < a10.length; h10++)
        l11[(i11 = a10[h10]).id()] = kn(i11, t17, o13.distance, o13.attributes, "kMedoids");
      c10 = false;
      for (var p10 = 0; p10 < t17.length; p10++) {
        var f11 = Cn(p10, a10, l11);
        if (0 !== f11.length) {
          u10[p10] = Tn(t17[p10], f11, o13.attributes);
          for (var v12 = 0; v12 < f11.length; v12++)
            (n13 = Tn(f11[v12], f11, o13.attributes)) < u10[p10] && (u10[p10] = n13, t17[p10] = f11[v12], c10 = true);
          s11[p10] = r10.collection(f11);
        }
      }
      d12++;
    }
    return s11;
  }, fuzzyCMeans: _n, fcm: _n };
  var In = ze({ distance: "euclidean", linkage: "min", mode: "threshold", threshold: 1 / 0, addDendrogram: false, dendrogramDepth: 0, attributes: [] });
  var zn = { single: "min", complete: "max" };
  var Ln = function(e22, t17, n13, r10, a10) {
    for (var i11, o13 = 0, s11 = 1 / 0, l11 = a10.attributes, u10 = function(e23, t18) {
      return mn(a10.distance, l11.length, function(t19) {
        return l11[t19](e23);
      }, function(e24) {
        return l11[e24](t18);
      }, e23, t18);
    }, c10 = 0; c10 < e22.length; c10++) {
      var d12 = e22[c10].key, h10 = n13[d12][r10[d12]];
      h10 < s11 && (o13 = d12, s11 = h10);
    }
    if ("threshold" === a10.mode && s11 >= a10.threshold || "dendrogram" === a10.mode && 1 === e22.length)
      return false;
    var p10, f11 = t17[o13], g9 = t17[r10[o13]];
    p10 = "dendrogram" === a10.mode ? { left: f11, right: g9, key: f11.key } : { value: f11.value.concat(g9.value), key: f11.key }, e22[f11.index] = p10, e22.splice(g9.index, 1), t17[f11.key] = p10;
    for (var v12 = 0; v12 < e22.length; v12++) {
      var y10 = e22[v12];
      f11.key === y10.key ? i11 = 1 / 0 : "min" === a10.linkage ? (i11 = n13[f11.key][y10.key], n13[f11.key][y10.key] > n13[g9.key][y10.key] && (i11 = n13[g9.key][y10.key])) : "max" === a10.linkage ? (i11 = n13[f11.key][y10.key], n13[f11.key][y10.key] < n13[g9.key][y10.key] && (i11 = n13[g9.key][y10.key])) : i11 = "mean" === a10.linkage ? (n13[f11.key][y10.key] * f11.size + n13[g9.key][y10.key] * g9.size) / (f11.size + g9.size) : "dendrogram" === a10.mode ? u10(y10.value, f11.value) : u10(y10.value[0], f11.value[0]), n13[f11.key][y10.key] = n13[y10.key][f11.key] = i11;
    }
    for (var m12 = 0; m12 < e22.length; m12++) {
      var b11 = e22[m12].key;
      if (r10[b11] === f11.key || r10[b11] === g9.key) {
        for (var x11 = b11, w10 = 0; w10 < e22.length; w10++) {
          var E10 = e22[w10].key;
          n13[b11][E10] < n13[b11][x11] && (x11 = E10);
        }
        r10[b11] = x11;
      }
      e22[m12].index = m12;
    }
    return f11.key = g9.key = f11.index = g9.index = null, true;
  };
  var An = function e7(t17, n13, r10) {
    t17 && (t17.value ? n13.push(t17.value) : (t17.left && e7(t17.left, n13), t17.right && e7(t17.right, n13)));
  };
  var On = function e8(t17, n13) {
    if (!t17)
      return "";
    if (t17.left && t17.right) {
      var r10 = e8(t17.left, n13), a10 = e8(t17.right, n13), i11 = n13.add({ group: "nodes", data: { id: r10 + "," + a10 } });
      return n13.add({ group: "edges", data: { source: r10, target: i11.id() } }), n13.add({ group: "edges", data: { source: a10, target: i11.id() } }), i11.id();
    }
    return t17.value ? t17.value.id() : void 0;
  };
  var Rn = function e9(t17, n13, r10) {
    if (!t17)
      return [];
    var a10 = [], i11 = [], o13 = [];
    return 0 === n13 ? (t17.left && An(t17.left, a10), t17.right && An(t17.right, i11), o13 = a10.concat(i11), [r10.collection(o13)]) : 1 === n13 ? t17.value ? [r10.collection(t17.value)] : (t17.left && An(t17.left, a10), t17.right && An(t17.right, i11), [r10.collection(a10), r10.collection(i11)]) : t17.value ? [r10.collection(t17.value)] : (t17.left && (a10 = e9(t17.left, n13 - 1, r10)), t17.right && (i11 = e9(t17.right, n13 - 1, r10)), a10.concat(i11));
  };
  var Vn = function(e22) {
    for (var t17 = this.cy(), n13 = this.nodes(), r10 = function(e23) {
      var t18 = In(e23), n14 = zn[t18.linkage];
      return null != n14 && (t18.linkage = n14), t18;
    }(e22), a10 = r10.attributes, i11 = function(e23, t18) {
      return mn(r10.distance, a10.length, function(t19) {
        return a10[t19](e23);
      }, function(e24) {
        return a10[e24](t18);
      }, e23, t18);
    }, o13 = [], s11 = [], l11 = [], u10 = [], c10 = 0; c10 < n13.length; c10++) {
      var d12 = { value: "dendrogram" === r10.mode ? n13[c10] : [n13[c10]], key: c10, index: c10 };
      o13[c10] = d12, u10[c10] = d12, s11[c10] = [], l11[c10] = 0;
    }
    for (var h10 = 0; h10 < o13.length; h10++)
      for (var p10 = 0; p10 <= h10; p10++) {
        var f11 = void 0;
        f11 = "dendrogram" === r10.mode ? h10 === p10 ? 1 / 0 : i11(o13[h10].value, o13[p10].value) : h10 === p10 ? 1 / 0 : i11(o13[h10].value[0], o13[p10].value[0]), s11[h10][p10] = f11, s11[p10][h10] = f11, f11 < s11[h10][l11[h10]] && (l11[h10] = p10);
      }
    for (var g9, v12 = Ln(o13, u10, s11, l11, r10); v12; )
      v12 = Ln(o13, u10, s11, l11, r10);
    return "dendrogram" === r10.mode ? (g9 = Rn(o13[0], r10.dendrogramDepth, t17), r10.addDendrogram && On(o13[0], t17)) : (g9 = new Array(o13.length), o13.forEach(function(e23, n14) {
      e23.key = e23.index = null, g9[n14] = t17.collection(e23.value);
    })), g9;
  };
  var Fn = { hierarchicalClustering: Vn, hca: Vn };
  var qn = ze({ distance: "euclidean", preference: "median", damping: 0.8, maxIterations: 1e3, minIterations: 100, attributes: [] });
  var jn = function(e22, t17, n13, r10) {
    var a10 = function(e23, t18) {
      return r10[t18](e23);
    };
    return -mn(e22, r10.length, function(e23) {
      return a10(t17, e23);
    }, function(e23) {
      return a10(n13, e23);
    }, t17, n13);
  };
  var Yn = function(e22, t17) {
    var n13 = null;
    return n13 = "median" === t17 ? function(e23) {
      var t18 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : 0, n14 = arguments.length > 2 && void 0 !== arguments[2] ? arguments[2] : e23.length, r10 = !(arguments.length > 4 && void 0 !== arguments[4]) || arguments[4], a10 = !(arguments.length > 5 && void 0 !== arguments[5]) || arguments[5];
      arguments.length > 3 && void 0 !== arguments[3] && !arguments[3] ? (n14 < e23.length && e23.splice(n14, e23.length - n14), t18 > 0 && e23.splice(0, t18)) : e23 = e23.slice(t18, n14);
      for (var i11 = 0, o13 = e23.length - 1; o13 >= 0; o13--) {
        var s11 = e23[o13];
        a10 ? isFinite(s11) || (e23[o13] = -1 / 0, i11++) : e23.splice(o13, 1);
      }
      r10 && e23.sort(function(e24, t19) {
        return e24 - t19;
      });
      var l11 = e23.length, u10 = Math.floor(l11 / 2);
      return l11 % 2 != 0 ? e23[u10 + 1 + i11] : (e23[u10 - 1 + i11] + e23[u10 + i11]) / 2;
    }(e22) : "mean" === t17 ? function(e23) {
      for (var t18 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : 0, n14 = arguments.length > 2 && void 0 !== arguments[2] ? arguments[2] : e23.length, r10 = 0, a10 = 0, i11 = t18; i11 < n14; i11++) {
        var o13 = e23[i11];
        isFinite(o13) && (r10 += o13, a10++);
      }
      return r10 / a10;
    }(e22) : "min" === t17 ? function(e23) {
      for (var t18 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : 0, n14 = arguments.length > 2 && void 0 !== arguments[2] ? arguments[2] : e23.length, r10 = 1 / 0, a10 = t18; a10 < n14; a10++) {
        var i11 = e23[a10];
        isFinite(i11) && (r10 = Math.min(i11, r10));
      }
      return r10;
    }(e22) : "max" === t17 ? function(e23) {
      for (var t18 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : 0, n14 = arguments.length > 2 && void 0 !== arguments[2] ? arguments[2] : e23.length, r10 = -1 / 0, a10 = t18; a10 < n14; a10++) {
        var i11 = e23[a10];
        isFinite(i11) && (r10 = Math.max(i11, r10));
      }
      return r10;
    }(e22) : t17, n13;
  };
  var Xn = function(e22, t17, n13) {
    for (var r10 = [], a10 = 0; a10 < e22; a10++) {
      for (var i11 = -1, o13 = -1 / 0, s11 = 0; s11 < n13.length; s11++) {
        var l11 = n13[s11];
        t17[a10 * e22 + l11] > o13 && (i11 = l11, o13 = t17[a10 * e22 + l11]);
      }
      i11 > 0 && r10.push(i11);
    }
    for (var u10 = 0; u10 < n13.length; u10++)
      r10[n13[u10]] = n13[u10];
    return r10;
  };
  var Wn = function(e22) {
    for (var t17, n13, r10, a10, i11, o13, s11 = this.cy(), l11 = this.nodes(), u10 = function(e23) {
      var t18 = e23.damping, n14 = e23.preference;
      0.5 <= t18 && t18 < 1 || Pe("Damping must range on [0.5, 1).  Got: ".concat(t18));
      var r11 = ["median", "mean", "min", "max"];
      return r11.some(function(e24) {
        return e24 === n14;
      }) || I6(n14) || Pe("Preference must be one of [".concat(r11.map(function(e24) {
        return "'".concat(e24, "'");
      }).join(", "), "] or a number.  Got: ").concat(n14)), qn(e23);
    }(e22), c10 = {}, d12 = 0; d12 < l11.length; d12++)
      c10[l11[d12].id()] = d12;
    n13 = (t17 = l11.length) * t17, r10 = new Array(n13);
    for (var h10 = 0; h10 < n13; h10++)
      r10[h10] = -1 / 0;
    for (var p10 = 0; p10 < t17; p10++)
      for (var f11 = 0; f11 < t17; f11++)
        p10 !== f11 && (r10[p10 * t17 + f11] = jn(u10.distance, l11[p10], l11[f11], u10.attributes));
    a10 = Yn(r10, u10.preference);
    for (var g9 = 0; g9 < t17; g9++)
      r10[g9 * t17 + g9] = a10;
    i11 = new Array(n13);
    for (var v12 = 0; v12 < n13; v12++)
      i11[v12] = 0;
    o13 = new Array(n13);
    for (var y10 = 0; y10 < n13; y10++)
      o13[y10] = 0;
    for (var m12 = new Array(t17), b11 = new Array(t17), x11 = new Array(t17), w10 = 0; w10 < t17; w10++)
      m12[w10] = 0, b11[w10] = 0, x11[w10] = 0;
    for (var E10, k10 = new Array(t17 * u10.minIterations), C9 = 0; C9 < k10.length; C9++)
      k10[C9] = 0;
    for (E10 = 0; E10 < u10.maxIterations; E10++) {
      for (var S8 = 0; S8 < t17; S8++) {
        for (var D7 = -1 / 0, P10 = -1 / 0, T9 = -1, M9 = 0, B8 = 0; B8 < t17; B8++)
          m12[B8] = i11[S8 * t17 + B8], (M9 = o13[S8 * t17 + B8] + r10[S8 * t17 + B8]) >= D7 ? (P10 = D7, D7 = M9, T9 = B8) : M9 > P10 && (P10 = M9);
        for (var _7 = 0; _7 < t17; _7++)
          i11[S8 * t17 + _7] = (1 - u10.damping) * (r10[S8 * t17 + _7] - D7) + u10.damping * m12[_7];
        i11[S8 * t17 + T9] = (1 - u10.damping) * (r10[S8 * t17 + T9] - P10) + u10.damping * m12[T9];
      }
      for (var N8 = 0; N8 < t17; N8++) {
        for (var z8 = 0, L10 = 0; L10 < t17; L10++)
          m12[L10] = o13[L10 * t17 + N8], b11[L10] = Math.max(0, i11[L10 * t17 + N8]), z8 += b11[L10];
        z8 -= b11[N8], b11[N8] = i11[N8 * t17 + N8], z8 += b11[N8];
        for (var A10 = 0; A10 < t17; A10++)
          o13[A10 * t17 + N8] = (1 - u10.damping) * Math.min(0, z8 - b11[A10]) + u10.damping * m12[A10];
        o13[N8 * t17 + N8] = (1 - u10.damping) * (z8 - b11[N8]) + u10.damping * m12[N8];
      }
      for (var O9 = 0, R8 = 0; R8 < t17; R8++) {
        var V8 = o13[R8 * t17 + R8] + i11[R8 * t17 + R8] > 0 ? 1 : 0;
        k10[E10 % u10.minIterations * t17 + R8] = V8, O9 += V8;
      }
      if (O9 > 0 && (E10 >= u10.minIterations - 1 || E10 == u10.maxIterations - 1)) {
        for (var F9 = 0, q8 = 0; q8 < t17; q8++) {
          x11[q8] = 0;
          for (var j9 = 0; j9 < u10.minIterations; j9++)
            x11[q8] += k10[j9 * t17 + q8];
          0 !== x11[q8] && x11[q8] !== u10.minIterations || F9++;
        }
        if (F9 === t17)
          break;
      }
    }
    for (var Y6 = function(e23, t18, n14) {
      for (var r11 = [], a11 = 0; a11 < e23; a11++)
        t18[a11 * e23 + a11] + n14[a11 * e23 + a11] > 0 && r11.push(a11);
      return r11;
    }(t17, i11, o13), X6 = function(e23, t18, n14) {
      for (var r11 = Xn(e23, t18, n14), a11 = 0; a11 < n14.length; a11++) {
        for (var i12 = [], o14 = 0; o14 < r11.length; o14++)
          r11[o14] === n14[a11] && i12.push(o14);
        for (var s12 = -1, l12 = -1 / 0, u11 = 0; u11 < i12.length; u11++) {
          for (var c11 = 0, d13 = 0; d13 < i12.length; d13++)
            c11 += t18[i12[d13] * e23 + i12[u11]];
          c11 > l12 && (s12 = u11, l12 = c11);
        }
        n14[a11] = i12[s12];
      }
      return Xn(e23, t18, n14);
    }(t17, r10, Y6), W8 = {}, H8 = 0; H8 < Y6.length; H8++)
      W8[Y6[H8]] = [];
    for (var K6 = 0; K6 < l11.length; K6++) {
      var G6 = X6[c10[l11[K6].id()]];
      null != G6 && W8[G6].push(l11[K6]);
    }
    for (var U7 = new Array(Y6.length), Z6 = 0; Z6 < Y6.length; Z6++)
      U7[Z6] = s11.collection(W8[Y6[Z6]]);
    return U7;
  };
  var Hn = { affinityPropagation: Wn, ap: Wn };
  var Kn = ze({ root: void 0, directed: false });
  var Gn = function() {
    var e22 = this, t17 = {}, n13 = 0, r10 = 0, a10 = [], i11 = [], o13 = {}, s11 = function s12(l12, u10, c10) {
      l12 === c10 && (r10 += 1), t17[u10] = { id: n13, low: n13++, cutVertex: false };
      var d12, h10, p10, f11, g9 = e22.getElementById(u10).connectedEdges().intersection(e22);
      0 === g9.size() ? a10.push(e22.spawn(e22.getElementById(u10))) : g9.forEach(function(n14) {
        d12 = n14.source().id(), h10 = n14.target().id(), (p10 = d12 === u10 ? h10 : d12) !== c10 && (f11 = n14.id(), o13[f11] || (o13[f11] = true, i11.push({ x: u10, y: p10, edge: n14 })), p10 in t17 ? t17[u10].low = Math.min(t17[u10].low, t17[p10].id) : (s12(l12, p10, u10), t17[u10].low = Math.min(t17[u10].low, t17[p10].low), t17[u10].id <= t17[p10].low && (t17[u10].cutVertex = true, function(n15, r11) {
          for (var o14 = i11.length - 1, s13 = [], l13 = e22.spawn(); i11[o14].x != n15 || i11[o14].y != r11; )
            s13.push(i11.pop().edge), o14--;
          s13.push(i11.pop().edge), s13.forEach(function(n16) {
            var r12 = n16.connectedNodes().intersection(e22);
            l13.merge(n16), r12.forEach(function(n17) {
              var r13 = n17.id(), a11 = n17.connectedEdges().intersection(e22);
              l13.merge(n17), t17[r13].cutVertex ? l13.merge(a11.filter(function(e23) {
                return e23.isLoop();
              })) : l13.merge(a11);
            });
          }), a10.push(l13);
        }(u10, p10))));
      });
    };
    e22.forEach(function(e23) {
      if (e23.isNode()) {
        var n14 = e23.id();
        n14 in t17 || (r10 = 0, s11(n14, n14), t17[n14].cutVertex = r10 > 1);
      }
    });
    var l11 = Object.keys(t17).filter(function(e23) {
      return t17[e23].cutVertex;
    }).map(function(t18) {
      return e22.getElementById(t18);
    });
    return { cut: e22.spawn(l11), components: a10 };
  };
  var Un = function() {
    var e22 = this, t17 = {}, n13 = 0, r10 = [], a10 = [], i11 = e22.spawn(e22), o13 = function o14(s11) {
      if (a10.push(s11), t17[s11] = { index: n13, low: n13++, explored: false }, e22.getElementById(s11).connectedEdges().intersection(e22).forEach(function(e23) {
        var n14 = e23.target().id();
        n14 !== s11 && (n14 in t17 || o14(n14), t17[n14].explored || (t17[s11].low = Math.min(t17[s11].low, t17[n14].low)));
      }), t17[s11].index === t17[s11].low) {
        for (var l11 = e22.spawn(); ; ) {
          var u10 = a10.pop();
          if (l11.merge(e22.getElementById(u10)), t17[u10].low = t17[s11].index, t17[u10].explored = true, u10 === s11)
            break;
        }
        var c10 = l11.edgesWith(l11), d12 = l11.merge(c10);
        r10.push(d12), i11 = i11.difference(d12);
      }
    };
    return e22.forEach(function(e23) {
      if (e23.isNode()) {
        var n14 = e23.id();
        n14 in t17 || o13(n14);
      }
    }), { cut: i11, components: r10 };
  };
  var Zn = {};
  [Xe, He, Ke, Ue, $e, Je, rt4, Ht4, Gt4, Zt4, Qt4, un, Nn, Fn, Hn, { hierholzer: function(e22) {
    if (!N6(e22)) {
      var t17 = arguments;
      e22 = { root: t17[0], directed: t17[1] };
    }
    var n13, r10, a10, i11 = Kn(e22), o13 = i11.root, s11 = i11.directed, l11 = this, u10 = false;
    o13 && (a10 = M6(o13) ? this.filter(o13)[0].id() : o13[0].id());
    var c10 = {}, d12 = {};
    s11 ? l11.forEach(function(e23) {
      var t18 = e23.id();
      if (e23.isNode()) {
        var a11 = e23.indegree(true), i12 = e23.outdegree(true), o14 = a11 - i12, s12 = i12 - a11;
        1 == o14 ? n13 ? u10 = true : n13 = t18 : 1 == s12 ? r10 ? u10 = true : r10 = t18 : (s12 > 1 || o14 > 1) && (u10 = true), c10[t18] = [], e23.outgoers().forEach(function(e24) {
          e24.isEdge() && c10[t18].push(e24.id());
        });
      } else
        d12[t18] = [void 0, e23.target().id()];
    }) : l11.forEach(function(e23) {
      var t18 = e23.id();
      e23.isNode() ? (e23.degree(true) % 2 && (n13 ? r10 ? u10 = true : r10 = t18 : n13 = t18), c10[t18] = [], e23.connectedEdges().forEach(function(e24) {
        return c10[t18].push(e24.id());
      })) : d12[t18] = [e23.source().id(), e23.target().id()];
    });
    var h10 = { found: false, trail: void 0 };
    if (u10)
      return h10;
    if (r10 && n13)
      if (s11) {
        if (a10 && r10 != a10)
          return h10;
        a10 = r10;
      } else {
        if (a10 && r10 != a10 && n13 != a10)
          return h10;
        a10 || (a10 = r10);
      }
    else
      a10 || (a10 = l11[0].id());
    var p10 = function(e23) {
      for (var t18, n14, r11, a11 = e23, i12 = [e23]; c10[a11].length; )
        t18 = c10[a11].shift(), n14 = d12[t18][0], a11 != (r11 = d12[t18][1]) ? (c10[r11] = c10[r11].filter(function(e24) {
          return e24 != t18;
        }), a11 = r11) : s11 || a11 == n14 || (c10[n14] = c10[n14].filter(function(e24) {
          return e24 != t18;
        }), a11 = n14), i12.unshift(t18), i12.unshift(a11);
      return i12;
    }, f11 = [], g9 = [];
    for (g9 = p10(a10); 1 != g9.length; )
      0 == c10[g9[0]].length ? (f11.unshift(l11.getElementById(g9.shift())), f11.unshift(l11.getElementById(g9.shift()))) : g9 = p10(g9.shift()).concat(g9);
    for (var v12 in f11.unshift(l11.getElementById(g9.shift())), c10)
      if (c10[v12].length)
        return h10;
    return h10.found = true, h10.trail = this.spawn(f11, true), h10;
  } }, { hopcroftTarjanBiconnected: Gn, htbc: Gn, htb: Gn, hopcroftTarjanBiconnectedComponents: Gn }, { tarjanStronglyConnected: Un, tsc: Un, tscc: Un, tarjanStronglyConnectedComponents: Un }].forEach(function(e22) {
    J4(Zn, e22);
  });
  var $n = function e10(t17) {
    if (!(this instanceof e10))
      return new e10(t17);
    this.id = "Thenable/1.0.7", this.state = 0, this.fulfillValue = void 0, this.rejectReason = void 0, this.onFulfilled = [], this.onRejected = [], this.proxy = { then: this.then.bind(this) }, "function" == typeof t17 && t17.call(this, this.fulfill.bind(this), this.reject.bind(this));
  };
  $n.prototype = { fulfill: function(e22) {
    return Qn(this, 1, "fulfillValue", e22);
  }, reject: function(e22) {
    return Qn(this, 2, "rejectReason", e22);
  }, then: function(e22, t17) {
    var n13 = this, r10 = new $n();
    return n13.onFulfilled.push(tr4(e22, r10, "fulfill")), n13.onRejected.push(tr4(t17, r10, "reject")), Jn(n13), r10.proxy;
  } };
  var Qn = function(e22, t17, n13, r10) {
    return 0 === e22.state && (e22.state = t17, e22[n13] = r10, Jn(e22)), e22;
  };
  var Jn = function(e22) {
    1 === e22.state ? er4(e22, "onFulfilled", e22.fulfillValue) : 2 === e22.state && er4(e22, "onRejected", e22.rejectReason);
  };
  var er4 = function(e22, t17, n13) {
    if (0 !== e22[t17].length) {
      var r10 = e22[t17];
      e22[t17] = [];
      var a10 = function() {
        for (var e23 = 0; e23 < r10.length; e23++)
          r10[e23](n13);
      };
      "function" == typeof setImmediate ? setImmediate(a10) : setTimeout(a10, 0);
    }
  };
  var tr4 = function(e22, t17, n13) {
    return function(r10) {
      if ("function" != typeof e22)
        t17[n13].call(t17, r10);
      else {
        var a10;
        try {
          a10 = e22(r10);
        } catch (e23) {
          return void t17.reject(e23);
        }
        nr4(t17, a10);
      }
    };
  };
  var nr4 = function e11(t17, n13) {
    if (t17 !== n13 && t17.proxy !== n13) {
      var r10;
      if ("object" === g6(n13) && null !== n13 || "function" == typeof n13)
        try {
          r10 = n13.then;
        } catch (e22) {
          return void t17.reject(e22);
        }
      if ("function" != typeof r10)
        t17.fulfill(n13);
      else {
        var a10 = false;
        try {
          r10.call(n13, function(r11) {
            a10 || (a10 = true, r11 === n13 ? t17.reject(new TypeError("circular thenable chain")) : e11(t17, r11));
          }, function(e22) {
            a10 || (a10 = true, t17.reject(e22));
          });
        } catch (e22) {
          a10 || t17.reject(e22);
        }
      }
    } else
      t17.reject(new TypeError("cannot resolve promise with itself"));
  };
  $n.all = function(e22) {
    return new $n(function(t17, n13) {
      for (var r10 = new Array(e22.length), a10 = 0, i11 = function(n14, i12) {
        r10[n14] = i12, ++a10 === e22.length && t17(r10);
      }, o13 = 0; o13 < e22.length; o13++)
        !function(t18) {
          var r11 = e22[t18];
          null != r11 && null != r11.then ? r11.then(function(e23) {
            i11(t18, e23);
          }, function(e23) {
            n13(e23);
          }) : i11(t18, r11);
        }(o13);
    });
  }, $n.resolve = function(e22) {
    return new $n(function(t17, n13) {
      t17(e22);
    });
  }, $n.reject = function(e22) {
    return new $n(function(t17, n13) {
      n13(e22);
    });
  };
  var rr4 = "undefined" != typeof Promise ? Promise : $n;
  var ar4 = function(e22, t17, n13) {
    var r10 = R4(e22), a10 = !r10, i11 = this._private = J4({ duration: 1e3 }, t17, n13);
    if (i11.target = e22, i11.style = i11.style || i11.css, i11.started = false, i11.playing = false, i11.hooked = false, i11.applying = false, i11.progress = 0, i11.completes = [], i11.frames = [], i11.complete && B4(i11.complete) && i11.completes.push(i11.complete), a10) {
      var o13 = e22.position();
      i11.startPosition = i11.startPosition || { x: o13.x, y: o13.y }, i11.startStyle = i11.startStyle || e22.cy().style().getAnimationStartStyle(e22, i11.style);
    }
    if (r10) {
      var s11 = e22.pan();
      i11.startPan = { x: s11.x, y: s11.y }, i11.startZoom = e22.zoom();
    }
    this.length = 1, this[0] = this;
  };
  var ir4 = ar4.prototype;
  J4(ir4, { instanceString: function() {
    return "animation";
  }, hook: function() {
    var e22 = this._private;
    if (!e22.hooked) {
      var t17 = e22.target._private.animation;
      (e22.queue ? t17.queue : t17.current).push(this), L5(e22.target) && e22.target.cy().addToAnimationPool(e22.target), e22.hooked = true;
    }
    return this;
  }, play: function() {
    var e22 = this._private;
    return 1 === e22.progress && (e22.progress = 0), e22.playing = true, e22.started = false, e22.stopped = false, this.hook(), this;
  }, playing: function() {
    return this._private.playing;
  }, apply: function() {
    var e22 = this._private;
    return e22.applying = true, e22.started = false, e22.stopped = false, this.hook(), this;
  }, applying: function() {
    return this._private.applying;
  }, pause: function() {
    var e22 = this._private;
    return e22.playing = false, e22.started = false, this;
  }, stop: function() {
    var e22 = this._private;
    return e22.playing = false, e22.started = false, e22.stopped = true, this;
  }, rewind: function() {
    return this.progress(0);
  }, fastforward: function() {
    return this.progress(1);
  }, time: function(e22) {
    var t17 = this._private;
    return void 0 === e22 ? t17.progress * t17.duration : this.progress(e22 / t17.duration);
  }, progress: function(e22) {
    var t17 = this._private, n13 = t17.playing;
    return void 0 === e22 ? t17.progress : (n13 && this.pause(), t17.progress = e22, t17.started = false, n13 && this.play(), this);
  }, completed: function() {
    return 1 === this._private.progress;
  }, reverse: function() {
    var e22 = this._private, t17 = e22.playing;
    t17 && this.pause(), e22.progress = 1 - e22.progress, e22.started = false;
    var n13 = function(t18, n14) {
      var r11 = e22[t18];
      null != r11 && (e22[t18] = e22[n14], e22[n14] = r11);
    };
    if (n13("zoom", "startZoom"), n13("pan", "startPan"), n13("position", "startPosition"), e22.style)
      for (var r10 = 0; r10 < e22.style.length; r10++) {
        var a10 = e22.style[r10], i11 = a10.name, o13 = e22.startStyle[i11];
        e22.startStyle[i11] = a10, e22.style[r10] = o13;
      }
    return t17 && this.play(), this;
  }, promise: function(e22) {
    var t17, n13 = this._private;
    if ("frame" === e22)
      t17 = n13.frames;
    else
      t17 = n13.completes;
    return new rr4(function(e23, n14) {
      t17.push(function() {
        e23();
      });
    });
  } }), ir4.complete = ir4.completed, ir4.run = ir4.play, ir4.running = ir4.playing;
  var or4 = { animated: function() {
    return function() {
      var e22 = this, t17 = void 0 !== e22.length ? e22 : [e22];
      if (!(this._private.cy || this).styleEnabled())
        return false;
      var n13 = t17[0];
      return n13 ? n13._private.animation.current.length > 0 : void 0;
    };
  }, clearQueue: function() {
    return function() {
      var e22 = this, t17 = void 0 !== e22.length ? e22 : [e22];
      if (!(this._private.cy || this).styleEnabled())
        return this;
      for (var n13 = 0; n13 < t17.length; n13++) {
        t17[n13]._private.animation.queue = [];
      }
      return this;
    };
  }, delay: function() {
    return function(e22, t17) {
      return (this._private.cy || this).styleEnabled() ? this.animate({ delay: e22, duration: e22, complete: t17 }) : this;
    };
  }, delayAnimation: function() {
    return function(e22, t17) {
      return (this._private.cy || this).styleEnabled() ? this.animation({ delay: e22, duration: e22, complete: t17 }) : this;
    };
  }, animation: function() {
    return function(e22, t17) {
      var n13 = this, r10 = void 0 !== n13.length, a10 = r10 ? n13 : [n13], i11 = this._private.cy || this, o13 = !r10, s11 = !o13;
      if (!i11.styleEnabled())
        return this;
      var l11 = i11.style();
      if (e22 = J4({}, e22, t17), 0 === Object.keys(e22).length)
        return new ar4(a10[0], e22);
      switch (void 0 === e22.duration && (e22.duration = 400), e22.duration) {
        case "slow":
          e22.duration = 600;
          break;
        case "fast":
          e22.duration = 200;
      }
      if (s11 && (e22.style = l11.getPropsList(e22.style || e22.css), e22.css = void 0), s11 && null != e22.renderedPosition) {
        var u10 = e22.renderedPosition, c10 = i11.pan(), d12 = i11.zoom();
        e22.position = it4(u10, d12, c10);
      }
      if (o13 && null != e22.panBy) {
        var h10 = e22.panBy, p10 = i11.pan();
        e22.pan = { x: p10.x + h10.x, y: p10.y + h10.y };
      }
      var f11 = e22.center || e22.centre;
      if (o13 && null != f11) {
        var g9 = i11.getCenterPan(f11.eles, e22.zoom);
        null != g9 && (e22.pan = g9);
      }
      if (o13 && null != e22.fit) {
        var v12 = e22.fit, y10 = i11.getFitViewport(v12.eles || v12.boundingBox, v12.padding);
        null != y10 && (e22.pan = y10.pan, e22.zoom = y10.zoom);
      }
      if (o13 && N6(e22.zoom)) {
        var m12 = i11.getZoomedViewport(e22.zoom);
        null != m12 ? (m12.zoomed && (e22.zoom = m12.zoom), m12.panned && (e22.pan = m12.pan)) : e22.zoom = null;
      }
      return new ar4(a10[0], e22);
    };
  }, animate: function() {
    return function(e22, t17) {
      var n13 = this, r10 = void 0 !== n13.length ? n13 : [n13];
      if (!(this._private.cy || this).styleEnabled())
        return this;
      t17 && (e22 = J4({}, e22, t17));
      for (var a10 = 0; a10 < r10.length; a10++) {
        var i11 = r10[a10], o13 = i11.animated() && (void 0 === e22.queue || e22.queue);
        i11.animation(e22, o13 ? { queue: true } : void 0).play();
      }
      return this;
    };
  }, stop: function() {
    return function(e22, t17) {
      var n13 = this, r10 = void 0 !== n13.length ? n13 : [n13], a10 = this._private.cy || this;
      if (!a10.styleEnabled())
        return this;
      for (var i11 = 0; i11 < r10.length; i11++) {
        for (var o13 = r10[i11]._private, s11 = o13.animation.current, l11 = 0; l11 < s11.length; l11++) {
          var u10 = s11[l11]._private;
          t17 && (u10.duration = 0);
        }
        e22 && (o13.animation.queue = []), t17 || (o13.animation.current = []);
      }
      return a10.notify("draw"), this;
    };
  } };
  var sr2 = { data: function(e22) {
    return e22 = J4({}, { field: "data", bindingEvent: "data", allowBinding: false, allowSetting: false, allowGetting: false, settingEvent: "data", settingTriggersEvent: false, triggerFnName: "trigger", immutableKeys: {}, updateStyle: false, beforeGet: function(e23) {
    }, beforeSet: function(e23, t17) {
    }, onSet: function(e23) {
    }, canSet: function(e23) {
      return true;
    } }, e22), function(t17, n13) {
      var r10 = e22, a10 = this, i11 = void 0 !== a10.length, o13 = i11 ? a10 : [a10], s11 = i11 ? a10[0] : a10;
      if (M6(t17)) {
        var l11, u10 = -1 !== t17.indexOf(".") && f6.default(t17);
        if (r10.allowGetting && void 0 === n13)
          return s11 && (r10.beforeGet(s11), l11 = u10 && void 0 === s11._private[r10.field][t17] ? h6.default(s11._private[r10.field], u10) : s11._private[r10.field][t17]), l11;
        if (r10.allowSetting && void 0 !== n13 && !r10.immutableKeys[t17]) {
          var c10 = b6({}, t17, n13);
          r10.beforeSet(a10, c10);
          for (var d12 = 0, g9 = o13.length; d12 < g9; d12++) {
            var v12 = o13[d12];
            r10.canSet(v12) && (u10 && void 0 === s11._private[r10.field][t17] ? p6.default(v12._private[r10.field], u10, n13) : v12._private[r10.field][t17] = n13);
          }
          r10.updateStyle && a10.updateStyle(), r10.onSet(a10), r10.settingTriggersEvent && a10[r10.triggerFnName](r10.settingEvent);
        }
      } else if (r10.allowSetting && N6(t17)) {
        var y10, m12, x11 = t17, w10 = Object.keys(x11);
        r10.beforeSet(a10, x11);
        for (var E10 = 0; E10 < w10.length; E10++) {
          if (m12 = x11[y10 = w10[E10]], !r10.immutableKeys[y10])
            for (var k10 = 0; k10 < o13.length; k10++) {
              var C9 = o13[k10];
              r10.canSet(C9) && (C9._private[r10.field][y10] = m12);
            }
        }
        r10.updateStyle && a10.updateStyle(), r10.onSet(a10), r10.settingTriggersEvent && a10[r10.triggerFnName](r10.settingEvent);
      } else if (r10.allowBinding && B4(t17)) {
        var S8 = t17;
        a10.on(r10.bindingEvent, S8);
      } else if (r10.allowGetting && void 0 === t17) {
        var D7;
        return s11 && (r10.beforeGet(s11), D7 = s11._private[r10.field]), D7;
      }
      return a10;
    };
  }, removeData: function(e22) {
    return e22 = J4({}, { field: "data", event: "data", triggerFnName: "trigger", triggerEvent: false, immutableKeys: {} }, e22), function(t17) {
      var n13 = e22, r10 = this, a10 = void 0 !== r10.length ? r10 : [r10];
      if (M6(t17)) {
        for (var i11 = t17.split(/\s+/), o13 = i11.length, s11 = 0; s11 < o13; s11++) {
          var l11 = i11[s11];
          if (!F6(l11)) {
            if (!n13.immutableKeys[l11])
              for (var u10 = 0, c10 = a10.length; u10 < c10; u10++)
                a10[u10]._private[n13.field][l11] = void 0;
          }
        }
        n13.triggerEvent && r10[n13.triggerFnName](n13.event);
      } else if (void 0 === t17) {
        for (var d12 = 0, h10 = a10.length; d12 < h10; d12++)
          for (var p10 = a10[d12]._private[n13.field], f11 = Object.keys(p10), g9 = 0; g9 < f11.length; g9++) {
            var v12 = f11[g9];
            !n13.immutableKeys[v12] && (p10[v12] = void 0);
          }
        n13.triggerEvent && r10[n13.triggerFnName](n13.event);
      }
      return r10;
    };
  } };
  var lr2 = { eventAliasesOn: function(e22) {
    var t17 = e22;
    t17.addListener = t17.listen = t17.bind = t17.on, t17.unlisten = t17.unbind = t17.off = t17.removeListener, t17.trigger = t17.emit, t17.pon = t17.promiseOn = function(e23, t18) {
      var n13 = this, r10 = Array.prototype.slice.call(arguments, 0);
      return new rr4(function(e24, t19) {
        var a10 = r10.concat([function(t20) {
          n13.off.apply(n13, i11), e24(t20);
        }]), i11 = a10.concat([]);
        n13.on.apply(n13, a10);
      });
    };
  } };
  var ur3 = {};
  [or4, sr2, lr2].forEach(function(e22) {
    J4(ur3, e22);
  });
  var cr3 = { animate: ur3.animate(), animation: ur3.animation(), animated: ur3.animated(), clearQueue: ur3.clearQueue(), delay: ur3.delay(), delayAnimation: ur3.delayAnimation(), stop: ur3.stop() };
  var dr2 = { classes: function(e22) {
    var t17 = this;
    if (void 0 === e22) {
      var n13 = [];
      return t17[0]._private.classes.forEach(function(e23) {
        return n13.push(e23);
      }), n13;
    }
    _5(e22) || (e22 = (e22 || "").match(/\S+/g) || []);
    for (var r10 = [], a10 = new qe(e22), i11 = 0; i11 < t17.length; i11++) {
      for (var o13 = t17[i11], s11 = o13._private, l11 = s11.classes, u10 = false, c10 = 0; c10 < e22.length; c10++) {
        var d12 = e22[c10];
        if (!l11.has(d12)) {
          u10 = true;
          break;
        }
      }
      u10 || (u10 = l11.size !== e22.length), u10 && (s11.classes = a10, r10.push(o13));
    }
    return r10.length > 0 && this.spawn(r10).updateStyle().emit("class"), t17;
  }, addClass: function(e22) {
    return this.toggleClass(e22, true);
  }, hasClass: function(e22) {
    var t17 = this[0];
    return null != t17 && t17._private.classes.has(e22);
  }, toggleClass: function(e22, t17) {
    _5(e22) || (e22 = e22.match(/\S+/g) || []);
    for (var n13 = this, r10 = void 0 === t17, a10 = [], i11 = 0, o13 = n13.length; i11 < o13; i11++)
      for (var s11 = n13[i11], l11 = s11._private.classes, u10 = false, c10 = 0; c10 < e22.length; c10++) {
        var d12 = e22[c10], h10 = l11.has(d12), p10 = false;
        t17 || r10 && !h10 ? (l11.add(d12), p10 = true) : (!t17 || r10 && h10) && (l11.delete(d12), p10 = true), !u10 && p10 && (a10.push(s11), u10 = true);
      }
    return a10.length > 0 && this.spawn(a10).updateStyle().emit("class"), n13;
  }, removeClass: function(e22) {
    return this.toggleClass(e22, false);
  }, flashClass: function(e22, t17) {
    var n13 = this;
    if (null == t17)
      t17 = 250;
    else if (0 === t17)
      return n13;
    return n13.addClass(e22), setTimeout(function() {
      n13.removeClass(e22);
    }, t17), n13;
  } };
  dr2.className = dr2.classNames = dr2.classes;
  var hr2 = { metaChar: "[\\!\\\"\\#\\$\\%\\&\\'\\(\\)\\*\\+\\,\\.\\/\\:\\;\\<\\=\\>\\?\\@\\[\\]\\^\\`\\{\\|\\}\\~]", comparatorOp: "=|\\!=|>|>=|<|<=|\\$=|\\^=|\\*=", boolOp: "\\?|\\!|\\^", string: `"(?:\\\\"|[^"])*"|'(?:\\\\'|[^'])*'`, number: K4, meta: "degree|indegree|outdegree", separator: "\\s*,\\s*", descendant: "\\s+", child: "\\s+>\\s+", subject: "\\$", group: "node|edge|\\*", directedEdge: "\\s+->\\s+", undirectedEdge: "\\s+<->\\s+" };
  hr2.variable = "(?:[\\w-.]|(?:\\\\" + hr2.metaChar + "))+", hr2.className = "(?:[\\w-]|(?:\\\\" + hr2.metaChar + "))+", hr2.value = hr2.string + "|" + hr2.number, hr2.id = hr2.variable, function() {
    var e22, t17, n13;
    for (e22 = hr2.comparatorOp.split("|"), n13 = 0; n13 < e22.length; n13++)
      t17 = e22[n13], hr2.comparatorOp += "|@" + t17;
    for (e22 = hr2.comparatorOp.split("|"), n13 = 0; n13 < e22.length; n13++)
      (t17 = e22[n13]).indexOf("!") >= 0 || "=" !== t17 && (hr2.comparatorOp += "|\\!" + t17);
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
  var zr = [{ selector: ":selected", matches: function(e22) {
    return e22.selected();
  } }, { selector: ":unselected", matches: function(e22) {
    return !e22.selected();
  } }, { selector: ":selectable", matches: function(e22) {
    return e22.selectable();
  } }, { selector: ":unselectable", matches: function(e22) {
    return !e22.selectable();
  } }, { selector: ":locked", matches: function(e22) {
    return e22.locked();
  } }, { selector: ":unlocked", matches: function(e22) {
    return !e22.locked();
  } }, { selector: ":visible", matches: function(e22) {
    return e22.visible();
  } }, { selector: ":hidden", matches: function(e22) {
    return !e22.visible();
  } }, { selector: ":transparent", matches: function(e22) {
    return e22.transparent();
  } }, { selector: ":grabbed", matches: function(e22) {
    return e22.grabbed();
  } }, { selector: ":free", matches: function(e22) {
    return !e22.grabbed();
  } }, { selector: ":removed", matches: function(e22) {
    return e22.removed();
  } }, { selector: ":inside", matches: function(e22) {
    return !e22.removed();
  } }, { selector: ":grabbable", matches: function(e22) {
    return e22.grabbable();
  } }, { selector: ":ungrabbable", matches: function(e22) {
    return !e22.grabbable();
  } }, { selector: ":animated", matches: function(e22) {
    return e22.animated();
  } }, { selector: ":unanimated", matches: function(e22) {
    return !e22.animated();
  } }, { selector: ":parent", matches: function(e22) {
    return e22.isParent();
  } }, { selector: ":childless", matches: function(e22) {
    return e22.isChildless();
  } }, { selector: ":child", matches: function(e22) {
    return e22.isChild();
  } }, { selector: ":orphan", matches: function(e22) {
    return e22.isOrphan();
  } }, { selector: ":nonorphan", matches: function(e22) {
    return e22.isChild();
  } }, { selector: ":compound", matches: function(e22) {
    return e22.isNode() ? e22.isParent() : e22.source().isParent() || e22.target().isParent();
  } }, { selector: ":loop", matches: function(e22) {
    return e22.isLoop();
  } }, { selector: ":simple", matches: function(e22) {
    return e22.isSimple();
  } }, { selector: ":active", matches: function(e22) {
    return e22.active();
  } }, { selector: ":inactive", matches: function(e22) {
    return !e22.active();
  } }, { selector: ":backgrounding", matches: function(e22) {
    return e22.backgrounding();
  } }, { selector: ":nonbackgrounding", matches: function(e22) {
    return !e22.backgrounding();
  } }].sort(function(e22, t17) {
    return function(e23, t18) {
      return -1 * Q4(e23, t18);
    }(e22.selector, t17.selector);
  });
  var Lr = function() {
    for (var e22, t17 = {}, n13 = 0; n13 < zr.length; n13++)
      t17[(e22 = zr[n13]).selector] = e22.matches;
    return t17;
  }();
  var Ar = "(" + zr.map(function(e22) {
    return e22.selector;
  }).join("|") + ")";
  var Or = function(e22) {
    return e22.replace(new RegExp("\\\\(" + hr2.metaChar + ")", "g"), function(e23, t17) {
      return t17;
    });
  };
  var Rr = function(e22, t17, n13) {
    e22[e22.length - 1] = n13;
  };
  var Vr = [{ name: "group", query: true, regex: "(" + hr2.group + ")", populate: function(e22, t17, n13) {
    var r10 = x6(n13, 1)[0];
    t17.checks.push({ type: pr2, value: "*" === r10 ? r10 : r10 + "s" });
  } }, { name: "state", query: true, regex: Ar, populate: function(e22, t17, n13) {
    var r10 = x6(n13, 1)[0];
    t17.checks.push({ type: xr, value: r10 });
  } }, { name: "id", query: true, regex: "\\#(" + hr2.id + ")", populate: function(e22, t17, n13) {
    var r10 = x6(n13, 1)[0];
    t17.checks.push({ type: wr, value: Or(r10) });
  } }, { name: "className", query: true, regex: "\\.(" + hr2.className + ")", populate: function(e22, t17, n13) {
    var r10 = x6(n13, 1)[0];
    t17.checks.push({ type: Er, value: Or(r10) });
  } }, { name: "dataExists", query: true, regex: "\\[\\s*(" + hr2.variable + ")\\s*\\]", populate: function(e22, t17, n13) {
    var r10 = x6(n13, 1)[0];
    t17.checks.push({ type: yr2, field: Or(r10) });
  } }, { name: "dataCompare", query: true, regex: "\\[\\s*(" + hr2.variable + ")\\s*(" + hr2.comparatorOp + ")\\s*(" + hr2.value + ")\\s*\\]", populate: function(e22, t17, n13) {
    var r10 = x6(n13, 3), a10 = r10[0], i11 = r10[1], o13 = r10[2];
    o13 = null != new RegExp("^" + hr2.string + "$").exec(o13) ? o13.substring(1, o13.length - 1) : parseFloat(o13), t17.checks.push({ type: vr2, field: Or(a10), operator: i11, value: o13 });
  } }, { name: "dataBool", query: true, regex: "\\[\\s*(" + hr2.boolOp + ")\\s*(" + hr2.variable + ")\\s*\\]", populate: function(e22, t17, n13) {
    var r10 = x6(n13, 2), a10 = r10[0], i11 = r10[1];
    t17.checks.push({ type: mr, field: Or(i11), operator: a10 });
  } }, { name: "metaCompare", query: true, regex: "\\[\\[\\s*(" + hr2.meta + ")\\s*(" + hr2.comparatorOp + ")\\s*(" + hr2.number + ")\\s*\\]\\]", populate: function(e22, t17, n13) {
    var r10 = x6(n13, 3), a10 = r10[0], i11 = r10[1], o13 = r10[2];
    t17.checks.push({ type: br2, field: Or(a10), operator: i11, value: parseFloat(o13) });
  } }, { name: "nextQuery", separator: true, regex: hr2.separator, populate: function(e22, t17) {
    var n13 = e22.currentSubject, r10 = e22.edgeCount, a10 = e22.compoundCount, i11 = e22[e22.length - 1];
    return null != n13 && (i11.subject = n13, e22.currentSubject = null), i11.edgeCount = r10, i11.compoundCount = a10, e22.edgeCount = 0, e22.compoundCount = 0, e22[e22.length++] = { checks: [] };
  } }, { name: "directedEdge", separator: true, regex: hr2.directedEdge, populate: function(e22, t17) {
    if (null == e22.currentSubject) {
      var n13 = { checks: [] }, r10 = t17, a10 = { checks: [] };
      return n13.checks.push({ type: Cr, source: r10, target: a10 }), Rr(e22, 0, n13), e22.edgeCount++, a10;
    }
    var i11 = { checks: [] }, o13 = t17, s11 = { checks: [] };
    return i11.checks.push({ type: Sr, source: o13, target: s11 }), Rr(e22, 0, i11), e22.edgeCount++, s11;
  } }, { name: "undirectedEdge", separator: true, regex: hr2.undirectedEdge, populate: function(e22, t17) {
    if (null == e22.currentSubject) {
      var n13 = { checks: [] }, r10 = t17, a10 = { checks: [] };
      return n13.checks.push({ type: kr, nodes: [r10, a10] }), Rr(e22, 0, n13), e22.edgeCount++, a10;
    }
    var i11 = { checks: [] }, o13 = t17, s11 = { checks: [] };
    return i11.checks.push({ type: Pr, node: o13, neighbor: s11 }), Rr(e22, 0, i11), s11;
  } }, { name: "child", separator: true, regex: hr2.child, populate: function(e22, t17) {
    if (null == e22.currentSubject) {
      var n13 = { checks: [] }, r10 = { checks: [] }, a10 = e22[e22.length - 1];
      return n13.checks.push({ type: Tr, parent: a10, child: r10 }), Rr(e22, 0, n13), e22.compoundCount++, r10;
    }
    if (e22.currentSubject === t17) {
      var i11 = { checks: [] }, o13 = e22[e22.length - 1], s11 = { checks: [] }, l11 = { checks: [] }, u10 = { checks: [] }, c10 = { checks: [] };
      return i11.checks.push({ type: Nr, left: o13, right: s11, subject: l11 }), l11.checks = t17.checks, t17.checks = [{ type: Ir }], c10.checks.push({ type: Ir }), s11.checks.push({ type: Br, parent: c10, child: u10 }), Rr(e22, 0, i11), e22.currentSubject = l11, e22.compoundCount++, u10;
    }
    var d12 = { checks: [] }, h10 = { checks: [] }, p10 = [{ type: Br, parent: d12, child: h10 }];
    return d12.checks = t17.checks, t17.checks = p10, e22.compoundCount++, h10;
  } }, { name: "descendant", separator: true, regex: hr2.descendant, populate: function(e22, t17) {
    if (null == e22.currentSubject) {
      var n13 = { checks: [] }, r10 = { checks: [] }, a10 = e22[e22.length - 1];
      return n13.checks.push({ type: Mr, ancestor: a10, descendant: r10 }), Rr(e22, 0, n13), e22.compoundCount++, r10;
    }
    if (e22.currentSubject === t17) {
      var i11 = { checks: [] }, o13 = e22[e22.length - 1], s11 = { checks: [] }, l11 = { checks: [] }, u10 = { checks: [] }, c10 = { checks: [] };
      return i11.checks.push({ type: Nr, left: o13, right: s11, subject: l11 }), l11.checks = t17.checks, t17.checks = [{ type: Ir }], c10.checks.push({ type: Ir }), s11.checks.push({ type: _r2, ancestor: c10, descendant: u10 }), Rr(e22, 0, i11), e22.currentSubject = l11, e22.compoundCount++, u10;
    }
    var d12 = { checks: [] }, h10 = { checks: [] }, p10 = [{ type: _r2, ancestor: d12, descendant: h10 }];
    return d12.checks = t17.checks, t17.checks = p10, e22.compoundCount++, h10;
  } }, { name: "subject", modifier: true, regex: hr2.subject, populate: function(e22, t17) {
    if (null != e22.currentSubject && e22.currentSubject !== t17)
      return Me("Redefinition of subject in selector `" + e22.toString() + "`"), false;
    e22.currentSubject = t17;
    var n13 = e22[e22.length - 1].checks[0], r10 = null == n13 ? null : n13.type;
    r10 === Cr ? n13.type = Dr : r10 === kr && (n13.type = Pr, n13.node = n13.nodes[1], n13.neighbor = n13.nodes[0], n13.nodes = null);
  } }];
  Vr.forEach(function(e22) {
    return e22.regexObj = new RegExp("^" + e22.regex);
  });
  var Fr = function(e22) {
    for (var t17, n13, r10, a10 = 0; a10 < Vr.length; a10++) {
      var i11 = Vr[a10], o13 = i11.name, s11 = e22.match(i11.regexObj);
      if (null != s11) {
        n13 = s11, t17 = i11, r10 = o13;
        var l11 = s11[0];
        e22 = e22.substring(l11.length);
        break;
      }
    }
    return { expr: t17, match: n13, name: r10, remaining: e22 };
  };
  var qr = { parse: function(e22) {
    var t17 = this, n13 = t17.inputText = e22, r10 = t17[0] = { checks: [] };
    for (t17.length = 1, n13 = function(e23) {
      var t18 = e23.match(/^\s+/);
      if (t18) {
        var n14 = t18[0];
        e23 = e23.substring(n14.length);
      }
      return e23;
    }(n13); ; ) {
      var a10 = Fr(n13);
      if (null == a10.expr)
        return Me("The selector `" + e22 + "`is invalid"), false;
      var i11 = a10.match.slice(1), o13 = a10.expr.populate(t17, r10, i11);
      if (false === o13)
        return false;
      if (null != o13 && (r10 = o13), (n13 = a10.remaining).match(/^\s*$/))
        break;
    }
    var s11 = t17[t17.length - 1];
    null != t17.currentSubject && (s11.subject = t17.currentSubject), s11.edgeCount = t17.edgeCount, s11.compoundCount = t17.compoundCount;
    for (var l11 = 0; l11 < t17.length; l11++) {
      var u10 = t17[l11];
      if (u10.compoundCount > 0 && u10.edgeCount > 0)
        return Me("The selector `" + e22 + "` is invalid because it uses both a compound selector and an edge selector"), false;
      if (u10.edgeCount > 1)
        return Me("The selector `" + e22 + "` is invalid because it uses multiple edge selectors"), false;
      1 === u10.edgeCount && Me("The selector `" + e22 + "` is deprecated.  Edge selectors do not take effect on changes to source and target nodes after an edge is added, for performance reasons.  Use a class or data selector on edges instead, updating the class or data of an edge when your app detects a change in source or target nodes.");
    }
    return true;
  }, toString: function() {
    if (null != this.toStringCache)
      return this.toStringCache;
    for (var e22 = function(e23) {
      return null == e23 ? "" : e23;
    }, t17 = function(t18) {
      return M6(t18) ? '"' + t18 + '"' : e22(t18);
    }, n13 = function(e23) {
      return " " + e23 + " ";
    }, r10 = function(r11, i12) {
      var o14 = r11.type, s12 = r11.value;
      switch (o14) {
        case pr2:
          var l11 = e22(s12);
          return l11.substring(0, l11.length - 1);
        case vr2:
          var u10 = r11.field, c10 = r11.operator;
          return "[" + u10 + n13(e22(c10)) + t17(s12) + "]";
        case mr:
          var d12 = r11.operator, h10 = r11.field;
          return "[" + e22(d12) + h10 + "]";
        case yr2:
          return "[" + r11.field + "]";
        case br2:
          var p10 = r11.operator;
          return "[[" + r11.field + n13(e22(p10)) + t17(s12) + "]]";
        case xr:
          return s12;
        case wr:
          return "#" + s12;
        case Er:
          return "." + s12;
        case Br:
        case Tr:
          return a10(r11.parent, i12) + n13(">") + a10(r11.child, i12);
        case _r2:
        case Mr:
          return a10(r11.ancestor, i12) + " " + a10(r11.descendant, i12);
        case Nr:
          var f11 = a10(r11.left, i12), g9 = a10(r11.subject, i12), v12 = a10(r11.right, i12);
          return f11 + (f11.length > 0 ? " " : "") + g9 + v12;
        case Ir:
          return "";
      }
    }, a10 = function(e23, t18) {
      return e23.checks.reduce(function(n14, a11, i12) {
        return n14 + (t18 === e23 && 0 === i12 ? "$" : "") + r10(a11, t18);
      }, "");
    }, i11 = "", o13 = 0; o13 < this.length; o13++) {
      var s11 = this[o13];
      i11 += a10(s11, s11.subject), this.length > 1 && o13 < this.length - 1 && (i11 += ", ");
    }
    return this.toStringCache = i11, i11;
  } };
  var jr = function(e22, t17, n13) {
    var r10, a10, i11, o13 = M6(e22), s11 = I6(e22), l11 = M6(n13), u10 = false, c10 = false, d12 = false;
    switch (t17.indexOf("!") >= 0 && (t17 = t17.replace("!", ""), c10 = true), t17.indexOf("@") >= 0 && (t17 = t17.replace("@", ""), u10 = true), (o13 || l11 || u10) && (a10 = o13 || s11 ? "" + e22 : "", i11 = "" + n13), u10 && (e22 = a10 = a10.toLowerCase(), n13 = i11 = i11.toLowerCase()), t17) {
      case "*=":
        r10 = a10.indexOf(i11) >= 0;
        break;
      case "$=":
        r10 = a10.indexOf(i11, a10.length - i11.length) >= 0;
        break;
      case "^=":
        r10 = 0 === a10.indexOf(i11);
        break;
      case "=":
        r10 = e22 === n13;
        break;
      case ">":
        d12 = true, r10 = e22 > n13;
        break;
      case ">=":
        d12 = true, r10 = e22 >= n13;
        break;
      case "<":
        d12 = true, r10 = e22 < n13;
        break;
      case "<=":
        d12 = true, r10 = e22 <= n13;
        break;
      default:
        r10 = false;
    }
    return !c10 || null == e22 && d12 || (r10 = !r10), r10;
  };
  var Yr = function(e22, t17) {
    return e22.data(t17);
  };
  var Xr = [];
  var Wr = function(e22, t17) {
    return e22.checks.every(function(e23) {
      return Xr[e23.type](e23, t17);
    });
  };
  Xr[pr2] = function(e22, t17) {
    var n13 = e22.value;
    return "*" === n13 || n13 === t17.group();
  }, Xr[xr] = function(e22, t17) {
    return function(e23, t18) {
      return Lr[e23](t18);
    }(e22.value, t17);
  }, Xr[wr] = function(e22, t17) {
    var n13 = e22.value;
    return t17.id() === n13;
  }, Xr[Er] = function(e22, t17) {
    var n13 = e22.value;
    return t17.hasClass(n13);
  }, Xr[br2] = function(e22, t17) {
    var n13 = e22.field, r10 = e22.operator, a10 = e22.value;
    return jr(function(e23, t18) {
      return e23[t18]();
    }(t17, n13), r10, a10);
  }, Xr[vr2] = function(e22, t17) {
    var n13 = e22.field, r10 = e22.operator, a10 = e22.value;
    return jr(Yr(t17, n13), r10, a10);
  }, Xr[mr] = function(e22, t17) {
    var n13 = e22.field, r10 = e22.operator;
    return function(e23, t18) {
      switch (t18) {
        case "?":
          return !!e23;
        case "!":
          return !e23;
        case "^":
          return void 0 === e23;
      }
    }(Yr(t17, n13), r10);
  }, Xr[yr2] = function(e22, t17) {
    var n13 = e22.field;
    return e22.operator, void 0 !== Yr(t17, n13);
  }, Xr[kr] = function(e22, t17) {
    var n13 = e22.nodes[0], r10 = e22.nodes[1], a10 = t17.source(), i11 = t17.target();
    return Wr(n13, a10) && Wr(r10, i11) || Wr(r10, a10) && Wr(n13, i11);
  }, Xr[Pr] = function(e22, t17) {
    return Wr(e22.node, t17) && t17.neighborhood().some(function(t18) {
      return t18.isNode() && Wr(e22.neighbor, t18);
    });
  }, Xr[Cr] = function(e22, t17) {
    return Wr(e22.source, t17.source()) && Wr(e22.target, t17.target());
  }, Xr[Sr] = function(e22, t17) {
    return Wr(e22.source, t17) && t17.outgoers().some(function(t18) {
      return t18.isNode() && Wr(e22.target, t18);
    });
  }, Xr[Dr] = function(e22, t17) {
    return Wr(e22.target, t17) && t17.incomers().some(function(t18) {
      return t18.isNode() && Wr(e22.source, t18);
    });
  }, Xr[Tr] = function(e22, t17) {
    return Wr(e22.child, t17) && Wr(e22.parent, t17.parent());
  }, Xr[Br] = function(e22, t17) {
    return Wr(e22.parent, t17) && t17.children().some(function(t18) {
      return Wr(e22.child, t18);
    });
  }, Xr[Mr] = function(e22, t17) {
    return Wr(e22.descendant, t17) && t17.ancestors().some(function(t18) {
      return Wr(e22.ancestor, t18);
    });
  }, Xr[_r2] = function(e22, t17) {
    return Wr(e22.ancestor, t17) && t17.descendants().some(function(t18) {
      return Wr(e22.descendant, t18);
    });
  }, Xr[Nr] = function(e22, t17) {
    return Wr(e22.subject, t17) && Wr(e22.left, t17) && Wr(e22.right, t17);
  }, Xr[Ir] = function() {
    return true;
  }, Xr[fr2] = function(e22, t17) {
    return e22.value.has(t17);
  }, Xr[gr2] = function(e22, t17) {
    return (0, e22.value)(t17);
  };
  var Hr = { matches: function(e22) {
    for (var t17 = 0; t17 < this.length; t17++) {
      var n13 = this[t17];
      if (Wr(n13, e22))
        return true;
    }
    return false;
  }, filter: function(e22) {
    var t17 = this;
    if (1 === t17.length && 1 === t17[0].checks.length && t17[0].checks[0].type === wr)
      return e22.getElementById(t17[0].checks[0].value).collection();
    var n13 = function(e23) {
      for (var n14 = 0; n14 < t17.length; n14++) {
        var r10 = t17[n14];
        if (Wr(r10, e23))
          return true;
      }
      return false;
    };
    return null == t17.text() && (n13 = function() {
      return true;
    }), e22.filter(n13);
  } };
  var Kr = function(e22) {
    this.inputText = e22, this.currentSubject = null, this.compoundCount = 0, this.edgeCount = 0, this.length = 0, null == e22 || M6(e22) && e22.match(/^\s*$/) || (L5(e22) ? this.addQuery({ checks: [{ type: fr2, value: e22.collection() }] }) : B4(e22) ? this.addQuery({ checks: [{ type: gr2, value: e22 }] }) : M6(e22) ? this.parse(e22) || (this.invalid = true) : Pe("A selector must be created from a string; found "));
  };
  var Gr = Kr.prototype;
  [qr, Hr].forEach(function(e22) {
    return J4(Gr, e22);
  }), Gr.text = function() {
    return this.inputText;
  }, Gr.size = function() {
    return this.length;
  }, Gr.eq = function(e22) {
    return this[e22];
  }, Gr.sameText = function(e22) {
    return !this.invalid && !e22.invalid && this.text() === e22.text();
  }, Gr.addQuery = function(e22) {
    this[this.length++] = e22;
  }, Gr.selector = Gr.toString;
  var Ur = { allAre: function(e22) {
    var t17 = new Kr(e22);
    return this.every(function(e23) {
      return t17.matches(e23);
    });
  }, is: function(e22) {
    var t17 = new Kr(e22);
    return this.some(function(e23) {
      return t17.matches(e23);
    });
  }, some: function(e22, t17) {
    for (var n13 = 0; n13 < this.length; n13++) {
      if (t17 ? e22.apply(t17, [this[n13], n13, this]) : e22(this[n13], n13, this))
        return true;
    }
    return false;
  }, every: function(e22, t17) {
    for (var n13 = 0; n13 < this.length; n13++) {
      if (!(t17 ? e22.apply(t17, [this[n13], n13, this]) : e22(this[n13], n13, this)))
        return false;
    }
    return true;
  }, same: function(e22) {
    if (this === e22)
      return true;
    e22 = this.cy().collection(e22);
    var t17 = this.length;
    return t17 === e22.length && (1 === t17 ? this[0] === e22[0] : this.every(function(t18) {
      return e22.hasElementWithId(t18.id());
    }));
  }, anySame: function(e22) {
    return e22 = this.cy().collection(e22), this.some(function(t17) {
      return e22.hasElementWithId(t17.id());
    });
  }, allAreNeighbors: function(e22) {
    e22 = this.cy().collection(e22);
    var t17 = this.neighborhood();
    return e22.every(function(e23) {
      return t17.hasElementWithId(e23.id());
    });
  }, contains: function(e22) {
    e22 = this.cy().collection(e22);
    var t17 = this;
    return e22.every(function(e23) {
      return t17.hasElementWithId(e23.id());
    });
  } };
  Ur.allAreNeighbours = Ur.allAreNeighbors, Ur.has = Ur.contains, Ur.equal = Ur.equals = Ur.same;
  var Zr;
  var $r;
  var Qr = function(e22, t17) {
    return function(n13, r10, a10, i11) {
      var o13, s11 = n13, l11 = this;
      if (null == s11 ? o13 = "" : L5(s11) && 1 === s11.length && (o13 = s11.id()), 1 === l11.length && o13) {
        var u10 = l11[0]._private, c10 = u10.traversalCache = u10.traversalCache || {}, d12 = c10[t17] = c10[t17] || [], h10 = ve(o13), p10 = d12[h10];
        return p10 || (d12[h10] = e22.call(l11, n13, r10, a10, i11));
      }
      return e22.call(l11, n13, r10, a10, i11);
    };
  };
  var Jr = { parent: function(e22) {
    var t17 = [];
    if (1 === this.length) {
      var n13 = this[0]._private.parent;
      if (n13)
        return n13;
    }
    for (var r10 = 0; r10 < this.length; r10++) {
      var a10 = this[r10]._private.parent;
      a10 && t17.push(a10);
    }
    return this.spawn(t17, true).filter(e22);
  }, parents: function(e22) {
    for (var t17 = [], n13 = this.parent(); n13.nonempty(); ) {
      for (var r10 = 0; r10 < n13.length; r10++) {
        var a10 = n13[r10];
        t17.push(a10);
      }
      n13 = n13.parent();
    }
    return this.spawn(t17, true).filter(e22);
  }, commonAncestors: function(e22) {
    for (var t17, n13 = 0; n13 < this.length; n13++) {
      var r10 = this[n13].parents();
      t17 = (t17 = t17 || r10).intersect(r10);
    }
    return t17.filter(e22);
  }, orphans: function(e22) {
    return this.stdFilter(function(e23) {
      return e23.isOrphan();
    }).filter(e22);
  }, nonorphans: function(e22) {
    return this.stdFilter(function(e23) {
      return e23.isChild();
    }).filter(e22);
  }, children: Qr(function(e22) {
    for (var t17 = [], n13 = 0; n13 < this.length; n13++)
      for (var r10 = this[n13]._private.children, a10 = 0; a10 < r10.length; a10++)
        t17.push(r10[a10]);
    return this.spawn(t17, true).filter(e22);
  }, "children"), siblings: function(e22) {
    return this.parent().children().not(this).filter(e22);
  }, isParent: function() {
    var e22 = this[0];
    if (e22)
      return e22.isNode() && 0 !== e22._private.children.length;
  }, isChildless: function() {
    var e22 = this[0];
    if (e22)
      return e22.isNode() && 0 === e22._private.children.length;
  }, isChild: function() {
    var e22 = this[0];
    if (e22)
      return e22.isNode() && null != e22._private.parent;
  }, isOrphan: function() {
    var e22 = this[0];
    if (e22)
      return e22.isNode() && null == e22._private.parent;
  }, descendants: function(e22) {
    var t17 = [];
    return function e23(n13) {
      for (var r10 = 0; r10 < n13.length; r10++) {
        var a10 = n13[r10];
        t17.push(a10), a10.children().nonempty() && e23(a10.children());
      }
    }(this.children()), this.spawn(t17, true).filter(e22);
  } };
  function ea(e22, t17, n13, r10) {
    for (var a10 = [], i11 = new qe(), o13 = e22.cy().hasCompoundNodes(), s11 = 0; s11 < e22.length; s11++) {
      var l11 = e22[s11];
      n13 ? a10.push(l11) : o13 && r10(a10, i11, l11);
    }
    for (; a10.length > 0; ) {
      var u10 = a10.shift();
      t17(u10), i11.add(u10.id()), o13 && r10(a10, i11, u10);
    }
    return e22;
  }
  function ta(e22, t17, n13) {
    if (n13.isParent())
      for (var r10 = n13._private.children, a10 = 0; a10 < r10.length; a10++) {
        var i11 = r10[a10];
        t17.has(i11.id()) || e22.push(i11);
      }
  }
  function na(e22, t17, n13) {
    if (n13.isChild()) {
      var r10 = n13._private.parent;
      t17.has(r10.id()) || e22.push(r10);
    }
  }
  function ra(e22, t17, n13) {
    na(e22, t17, n13), ta(e22, t17, n13);
  }
  Jr.forEachDown = function(e22) {
    return ea(this, e22, !(arguments.length > 1 && void 0 !== arguments[1]) || arguments[1], ta);
  }, Jr.forEachUp = function(e22) {
    return ea(this, e22, !(arguments.length > 1 && void 0 !== arguments[1]) || arguments[1], na);
  }, Jr.forEachUpAndDown = function(e22) {
    return ea(this, e22, !(arguments.length > 1 && void 0 !== arguments[1]) || arguments[1], ra);
  }, Jr.ancestors = Jr.parents, (Zr = $r = { data: ur3.data({ field: "data", bindingEvent: "data", allowBinding: true, allowSetting: true, settingEvent: "data", settingTriggersEvent: true, triggerFnName: "trigger", allowGetting: true, immutableKeys: { id: true, source: true, target: true, parent: true }, updateStyle: true }), removeData: ur3.removeData({ field: "data", event: "data", triggerFnName: "trigger", triggerEvent: true, immutableKeys: { id: true, source: true, target: true, parent: true }, updateStyle: true }), scratch: ur3.data({ field: "scratch", bindingEvent: "scratch", allowBinding: true, allowSetting: true, settingEvent: "scratch", settingTriggersEvent: true, triggerFnName: "trigger", allowGetting: true, updateStyle: true }), removeScratch: ur3.removeData({ field: "scratch", event: "scratch", triggerFnName: "trigger", triggerEvent: true, updateStyle: true }), rscratch: ur3.data({ field: "rscratch", allowBinding: false, allowSetting: true, settingTriggersEvent: false, allowGetting: true }), removeRscratch: ur3.removeData({ field: "rscratch", triggerEvent: false }), id: function() {
    var e22 = this[0];
    if (e22)
      return e22._private.data.id;
  } }).attr = Zr.data, Zr.removeAttr = Zr.removeData;
  var aa;
  var ia;
  var oa = $r;
  var sa = {};
  function la(e22) {
    return function(t17) {
      var n13 = this;
      if (void 0 === t17 && (t17 = true), 0 !== n13.length && n13.isNode() && !n13.removed()) {
        for (var r10 = 0, a10 = n13[0], i11 = a10._private.edges, o13 = 0; o13 < i11.length; o13++) {
          var s11 = i11[o13];
          !t17 && s11.isLoop() || (r10 += e22(a10, s11));
        }
        return r10;
      }
    };
  }
  function ua(e22, t17) {
    return function(n13) {
      for (var r10, a10 = this.nodes(), i11 = 0; i11 < a10.length; i11++) {
        var o13 = a10[i11][e22](n13);
        void 0 === o13 || void 0 !== r10 && !t17(o13, r10) || (r10 = o13);
      }
      return r10;
    };
  }
  J4(sa, { degree: la(function(e22, t17) {
    return t17.source().same(t17.target()) ? 2 : 1;
  }), indegree: la(function(e22, t17) {
    return t17.target().same(e22) ? 1 : 0;
  }), outdegree: la(function(e22, t17) {
    return t17.source().same(e22) ? 1 : 0;
  }) }), J4(sa, { minDegree: ua("degree", function(e22, t17) {
    return e22 < t17;
  }), maxDegree: ua("degree", function(e22, t17) {
    return e22 > t17;
  }), minIndegree: ua("indegree", function(e22, t17) {
    return e22 < t17;
  }), maxIndegree: ua("indegree", function(e22, t17) {
    return e22 > t17;
  }), minOutdegree: ua("outdegree", function(e22, t17) {
    return e22 < t17;
  }), maxOutdegree: ua("outdegree", function(e22, t17) {
    return e22 > t17;
  }) }), J4(sa, { totalDegree: function(e22) {
    for (var t17 = 0, n13 = this.nodes(), r10 = 0; r10 < n13.length; r10++)
      t17 += n13[r10].degree(e22);
    return t17;
  } });
  var ca = function(e22, t17, n13) {
    for (var r10 = 0; r10 < e22.length; r10++) {
      var a10 = e22[r10];
      if (!a10.locked()) {
        var i11 = a10._private.position, o13 = { x: null != t17.x ? t17.x - i11.x : 0, y: null != t17.y ? t17.y - i11.y : 0 };
        !a10.isParent() || 0 === o13.x && 0 === o13.y || a10.children().shift(o13, n13), a10.dirtyBoundingBoxCache();
      }
    }
  };
  var da = { field: "position", bindingEvent: "position", allowBinding: true, allowSetting: true, settingEvent: "position", settingTriggersEvent: true, triggerFnName: "emitAndNotify", allowGetting: true, validKeys: ["x", "y"], beforeGet: function(e22) {
    e22.updateCompoundBounds();
  }, beforeSet: function(e22, t17) {
    ca(e22, t17, false);
  }, onSet: function(e22) {
    e22.dirtyCompoundBoundsCache();
  }, canSet: function(e22) {
    return !e22.locked();
  } };
  aa = ia = { position: ur3.data(da), silentPosition: ur3.data(J4({}, da, { allowBinding: false, allowSetting: true, settingTriggersEvent: false, allowGetting: false, beforeSet: function(e22, t17) {
    ca(e22, t17, true);
  }, onSet: function(e22) {
    e22.dirtyCompoundBoundsCache();
  } })), positions: function(e22, t17) {
    if (N6(e22))
      t17 ? this.silentPosition(e22) : this.position(e22);
    else if (B4(e22)) {
      var n13 = e22, r10 = this.cy();
      r10.startBatch();
      for (var a10 = 0; a10 < this.length; a10++) {
        var i11, o13 = this[a10];
        (i11 = n13(o13, a10)) && (t17 ? o13.silentPosition(i11) : o13.position(i11));
      }
      r10.endBatch();
    }
    return this;
  }, silentPositions: function(e22) {
    return this.positions(e22, true);
  }, shift: function(e22, t17, n13) {
    var r10;
    if (N6(e22) ? (r10 = { x: I6(e22.x) ? e22.x : 0, y: I6(e22.y) ? e22.y : 0 }, n13 = t17) : M6(e22) && I6(t17) && ((r10 = { x: 0, y: 0 })[e22] = t17), null != r10) {
      var a10 = this.cy();
      a10.startBatch();
      for (var i11 = 0; i11 < this.length; i11++) {
        var o13 = this[i11];
        if (!(a10.hasCompoundNodes() && o13.isChild() && o13.ancestors().anySame(this))) {
          var s11 = o13.position(), l11 = { x: s11.x + r10.x, y: s11.y + r10.y };
          n13 ? o13.silentPosition(l11) : o13.position(l11);
        }
      }
      a10.endBatch();
    }
    return this;
  }, silentShift: function(e22, t17) {
    return N6(e22) ? this.shift(e22, true) : M6(e22) && I6(t17) && this.shift(e22, t17, true), this;
  }, renderedPosition: function(e22, t17) {
    var n13 = this[0], r10 = this.cy(), a10 = r10.zoom(), i11 = r10.pan(), o13 = N6(e22) ? e22 : void 0, s11 = void 0 !== o13 || void 0 !== t17 && M6(e22);
    if (n13 && n13.isNode()) {
      if (!s11) {
        var l11 = n13.position();
        return o13 = at4(l11, a10, i11), void 0 === e22 ? o13 : o13[e22];
      }
      for (var u10 = 0; u10 < this.length; u10++) {
        var c10 = this[u10];
        void 0 !== t17 ? c10.position(e22, (t17 - i11[e22]) / a10) : void 0 !== o13 && c10.position(it4(o13, a10, i11));
      }
    } else if (!s11)
      return;
    return this;
  }, relativePosition: function(e22, t17) {
    var n13 = this[0], r10 = this.cy(), a10 = N6(e22) ? e22 : void 0, i11 = void 0 !== a10 || void 0 !== t17 && M6(e22), o13 = r10.hasCompoundNodes();
    if (n13 && n13.isNode()) {
      if (!i11) {
        var s11 = n13.position(), l11 = o13 ? n13.parent() : null, u10 = l11 && l11.length > 0, c10 = u10;
        u10 && (l11 = l11[0]);
        var d12 = c10 ? l11.position() : { x: 0, y: 0 };
        return a10 = { x: s11.x - d12.x, y: s11.y - d12.y }, void 0 === e22 ? a10 : a10[e22];
      }
      for (var h10 = 0; h10 < this.length; h10++) {
        var p10 = this[h10], f11 = o13 ? p10.parent() : null, g9 = f11 && f11.length > 0, v12 = g9;
        g9 && (f11 = f11[0]);
        var y10 = v12 ? f11.position() : { x: 0, y: 0 };
        void 0 !== t17 ? p10.position(e22, t17 + y10[e22]) : void 0 !== a10 && p10.position({ x: a10.x + y10.x, y: a10.y + y10.y });
      }
    } else if (!i11)
      return;
    return this;
  } }, aa.modelPosition = aa.point = aa.position, aa.modelPositions = aa.points = aa.positions, aa.renderedPoint = aa.renderedPosition, aa.relativePoint = aa.relativePosition;
  var ha;
  var pa;
  var fa = ia;
  ha = pa = {}, pa.renderedBoundingBox = function(e22) {
    var t17 = this.boundingBox(e22), n13 = this.cy(), r10 = n13.zoom(), a10 = n13.pan(), i11 = t17.x1 * r10 + a10.x, o13 = t17.x2 * r10 + a10.x, s11 = t17.y1 * r10 + a10.y, l11 = t17.y2 * r10 + a10.y;
    return { x1: i11, x2: o13, y1: s11, y2: l11, w: o13 - i11, h: l11 - s11 };
  }, pa.dirtyCompoundBoundsCache = function() {
    var e22 = arguments.length > 0 && void 0 !== arguments[0] && arguments[0], t17 = this.cy();
    return t17.styleEnabled() && t17.hasCompoundNodes() ? (this.forEachUp(function(t18) {
      if (t18.isParent()) {
        var n13 = t18._private;
        n13.compoundBoundsClean = false, n13.bbCache = null, e22 || t18.emitAndNotify("bounds");
      }
    }), this) : this;
  }, pa.updateCompoundBounds = function() {
    var e22 = arguments.length > 0 && void 0 !== arguments[0] && arguments[0], t17 = this.cy();
    if (!t17.styleEnabled() || !t17.hasCompoundNodes())
      return this;
    if (!e22 && t17.batching())
      return this;
    function n13(e23) {
      if (e23.isParent()) {
        var t18 = e23._private, n14 = e23.children(), r11 = "include" === e23.pstyle("compound-sizing-wrt-labels").value, a11 = { width: { val: e23.pstyle("min-width").pfValue, left: e23.pstyle("min-width-bias-left"), right: e23.pstyle("min-width-bias-right") }, height: { val: e23.pstyle("min-height").pfValue, top: e23.pstyle("min-height-bias-top"), bottom: e23.pstyle("min-height-bias-bottom") } }, i12 = n14.boundingBox({ includeLabels: r11, includeOverlays: false, useCache: false }), o13 = t18.position;
        0 !== i12.w && 0 !== i12.h || ((i12 = { w: e23.pstyle("width").pfValue, h: e23.pstyle("height").pfValue }).x1 = o13.x - i12.w / 2, i12.x2 = o13.x + i12.w / 2, i12.y1 = o13.y - i12.h / 2, i12.y2 = o13.y + i12.h / 2);
        var s11 = a11.width.left.value;
        "px" === a11.width.left.units && a11.width.val > 0 && (s11 = 100 * s11 / a11.width.val);
        var l11 = a11.width.right.value;
        "px" === a11.width.right.units && a11.width.val > 0 && (l11 = 100 * l11 / a11.width.val);
        var u10 = a11.height.top.value;
        "px" === a11.height.top.units && a11.height.val > 0 && (u10 = 100 * u10 / a11.height.val);
        var c10 = a11.height.bottom.value;
        "px" === a11.height.bottom.units && a11.height.val > 0 && (c10 = 100 * c10 / a11.height.val);
        var d12 = y10(a11.width.val - i12.w, s11, l11), h10 = d12.biasDiff, p10 = d12.biasComplementDiff, f11 = y10(a11.height.val - i12.h, u10, c10), g9 = f11.biasDiff, v12 = f11.biasComplementDiff;
        t18.autoPadding = function(e24, t19, n15, r12) {
          if ("%" !== n15.units)
            return "px" === n15.units ? n15.pfValue : 0;
          switch (r12) {
            case "width":
              return e24 > 0 ? n15.pfValue * e24 : 0;
            case "height":
              return t19 > 0 ? n15.pfValue * t19 : 0;
            case "average":
              return e24 > 0 && t19 > 0 ? n15.pfValue * (e24 + t19) / 2 : 0;
            case "min":
              return e24 > 0 && t19 > 0 ? e24 > t19 ? n15.pfValue * t19 : n15.pfValue * e24 : 0;
            case "max":
              return e24 > 0 && t19 > 0 ? e24 > t19 ? n15.pfValue * e24 : n15.pfValue * t19 : 0;
            default:
              return 0;
          }
        }(i12.w, i12.h, e23.pstyle("padding"), e23.pstyle("padding-relative-to").value), t18.autoWidth = Math.max(i12.w, a11.width.val), o13.x = (-h10 + i12.x1 + i12.x2 + p10) / 2, t18.autoHeight = Math.max(i12.h, a11.height.val), o13.y = (-g9 + i12.y1 + i12.y2 + v12) / 2;
      }
      function y10(e24, t19, n15) {
        var r12 = 0, a12 = 0, i13 = t19 + n15;
        return e24 > 0 && i13 > 0 && (r12 = t19 / i13 * e24, a12 = n15 / i13 * e24), { biasDiff: r12, biasComplementDiff: a12 };
      }
    }
    for (var r10 = 0; r10 < this.length; r10++) {
      var a10 = this[r10], i11 = a10._private;
      i11.compoundBoundsClean && !e22 || (n13(a10), t17.batching() || (i11.compoundBoundsClean = true));
    }
    return this;
  };
  var ga = function(e22) {
    return e22 === 1 / 0 || e22 === -1 / 0 ? 0 : e22;
  };
  var va = function(e22, t17, n13, r10, a10) {
    r10 - t17 != 0 && a10 - n13 != 0 && null != t17 && null != n13 && null != r10 && null != a10 && (e22.x1 = t17 < e22.x1 ? t17 : e22.x1, e22.x2 = r10 > e22.x2 ? r10 : e22.x2, e22.y1 = n13 < e22.y1 ? n13 : e22.y1, e22.y2 = a10 > e22.y2 ? a10 : e22.y2, e22.w = e22.x2 - e22.x1, e22.h = e22.y2 - e22.y1);
  };
  var ya = function(e22, t17) {
    return null == t17 ? e22 : va(e22, t17.x1, t17.y1, t17.x2, t17.y2);
  };
  var ma = function(e22, t17, n13) {
    return Oe(e22, t17, n13);
  };
  var ba = function(e22, t17, n13) {
    if (!t17.cy().headless()) {
      var r10, a10, i11 = t17._private, o13 = i11.rstyle, s11 = o13.arrowWidth / 2;
      if ("none" !== t17.pstyle(n13 + "-arrow-shape").value) {
        "source" === n13 ? (r10 = o13.srcX, a10 = o13.srcY) : "target" === n13 ? (r10 = o13.tgtX, a10 = o13.tgtY) : (r10 = o13.midX, a10 = o13.midY);
        var l11 = i11.arrowBounds = i11.arrowBounds || {}, u10 = l11[n13] = l11[n13] || {};
        u10.x1 = r10 - s11, u10.y1 = a10 - s11, u10.x2 = r10 + s11, u10.y2 = a10 + s11, u10.w = u10.x2 - u10.x1, u10.h = u10.y2 - u10.y1, mt4(u10, 1), va(e22, u10.x1, u10.y1, u10.x2, u10.y2);
      }
    }
  };
  var xa = function(e22, t17, n13) {
    if (!t17.cy().headless()) {
      var r10;
      r10 = n13 ? n13 + "-" : "";
      var a10 = t17._private, i11 = a10.rstyle;
      if (t17.pstyle(r10 + "label").strValue) {
        var o13, s11, l11, u10, c10 = t17.pstyle("text-halign"), d12 = t17.pstyle("text-valign"), h10 = ma(i11, "labelWidth", n13), p10 = ma(i11, "labelHeight", n13), f11 = ma(i11, "labelX", n13), g9 = ma(i11, "labelY", n13), v12 = t17.pstyle(r10 + "text-margin-x").pfValue, y10 = t17.pstyle(r10 + "text-margin-y").pfValue, m12 = t17.isEdge(), b11 = t17.pstyle(r10 + "text-rotation"), x11 = t17.pstyle("text-outline-width").pfValue, w10 = t17.pstyle("text-border-width").pfValue / 2, E10 = t17.pstyle("text-background-padding").pfValue, k10 = p10, C9 = h10, S8 = C9 / 2, D7 = k10 / 2;
        if (m12)
          o13 = f11 - S8, s11 = f11 + S8, l11 = g9 - D7, u10 = g9 + D7;
        else {
          switch (c10.value) {
            case "left":
              o13 = f11 - C9, s11 = f11;
              break;
            case "center":
              o13 = f11 - S8, s11 = f11 + S8;
              break;
            case "right":
              o13 = f11, s11 = f11 + C9;
          }
          switch (d12.value) {
            case "top":
              l11 = g9 - k10, u10 = g9;
              break;
            case "center":
              l11 = g9 - D7, u10 = g9 + D7;
              break;
            case "bottom":
              l11 = g9, u10 = g9 + k10;
          }
        }
        o13 += v12 - Math.max(x11, w10) - E10 - 2, s11 += v12 + Math.max(x11, w10) + E10 + 2, l11 += y10 - Math.max(x11, w10) - E10 - 2, u10 += y10 + Math.max(x11, w10) + E10 + 2;
        var P10 = n13 || "main", T9 = a10.labelBounds, M9 = T9[P10] = T9[P10] || {};
        M9.x1 = o13, M9.y1 = l11, M9.x2 = s11, M9.y2 = u10, M9.w = s11 - o13, M9.h = u10 - l11;
        var B8 = m12 && "autorotate" === b11.strValue, _7 = null != b11.pfValue && 0 !== b11.pfValue;
        if (B8 || _7) {
          var N8 = B8 ? ma(a10.rstyle, "labelAngle", n13) : b11.pfValue, I8 = Math.cos(N8), z8 = Math.sin(N8), L10 = (o13 + s11) / 2, A10 = (l11 + u10) / 2;
          if (!m12) {
            switch (c10.value) {
              case "left":
                L10 = s11;
                break;
              case "right":
                L10 = o13;
            }
            switch (d12.value) {
              case "top":
                A10 = u10;
                break;
              case "bottom":
                A10 = l11;
            }
          }
          var O9 = function(e23, t18) {
            return { x: (e23 -= L10) * I8 - (t18 -= A10) * z8 + L10, y: e23 * z8 + t18 * I8 + A10 };
          }, R8 = O9(o13, l11), V8 = O9(o13, u10), F9 = O9(s11, l11), q8 = O9(s11, u10);
          o13 = Math.min(R8.x, V8.x, F9.x, q8.x), s11 = Math.max(R8.x, V8.x, F9.x, q8.x), l11 = Math.min(R8.y, V8.y, F9.y, q8.y), u10 = Math.max(R8.y, V8.y, F9.y, q8.y);
        }
        var j9 = P10 + "Rot", Y6 = T9[j9] = T9[j9] || {};
        Y6.x1 = o13, Y6.y1 = l11, Y6.x2 = s11, Y6.y2 = u10, Y6.w = s11 - o13, Y6.h = u10 - l11, va(e22, o13, l11, s11, u10), va(a10.labelBounds.all, o13, l11, s11, u10);
      }
      return e22;
    }
  };
  var wa = function(e22) {
    var t17 = 0, n13 = function(e23) {
      return (e23 ? 1 : 0) << t17++;
    }, r10 = 0;
    return r10 += n13(e22.incudeNodes), r10 += n13(e22.includeEdges), r10 += n13(e22.includeLabels), r10 += n13(e22.includeMainLabels), r10 += n13(e22.includeSourceLabels), r10 += n13(e22.includeTargetLabels), r10 += n13(e22.includeOverlays);
  };
  var Ea = function(e22) {
    if (e22.isEdge()) {
      var t17 = e22.source().position(), n13 = e22.target().position(), r10 = function(e23) {
        return Math.round(e23);
      };
      return function(e23, t18) {
        var n14 = { value: 0, done: false }, r11 = 0, a10 = e23.length;
        return de({ next: function() {
          return r11 < a10 ? n14.value = e23[r11++] : n14.done = true, n14;
        } }, t18);
      }([r10(t17.x), r10(t17.y), r10(n13.x), r10(n13.y)]);
    }
    return 0;
  };
  var ka = function(e22, t17) {
    var n13, r10 = e22._private, a10 = e22.isEdge(), i11 = (null == t17 ? Sa : wa(t17)) === Sa, o13 = Ea(e22), s11 = r10.bbCachePosKey === o13, l11 = t17.useCache && s11, u10 = function(e23) {
      return null == e23._private.bbCache || e23._private.styleDirty;
    };
    if (!l11 || u10(e22) || a10 && u10(e22.source()) || u10(e22.target()) ? (s11 || e22.recalculateRenderedStyle(l11), n13 = function(e23, t18) {
      var n14, r11, a11, i12, o14, s12, l12, u11 = e23._private.cy, c11 = u11.styleEnabled(), d12 = u11.headless(), h10 = vt4(), p10 = e23._private, f11 = e23.isNode(), g9 = e23.isEdge(), v12 = p10.rstyle, y10 = f11 && c11 ? e23.pstyle("bounds-expansion").pfValue : [0], m12 = function(e24) {
        return "none" !== e24.pstyle("display").value;
      }, b11 = !c11 || m12(e23) && (!g9 || m12(e23.source()) && m12(e23.target()));
      if (b11) {
        var x11 = 0;
        c11 && t18.includeOverlays && 0 !== e23.pstyle("overlay-opacity").value && (x11 = e23.pstyle("overlay-padding").value);
        var w10 = 0;
        c11 && t18.includeUnderlays && 0 !== e23.pstyle("underlay-opacity").value && (w10 = e23.pstyle("underlay-padding").value);
        var E10 = Math.max(x11, w10), k10 = 0;
        if (c11 && (k10 = e23.pstyle("width").pfValue / 2), f11 && t18.includeNodes) {
          var C9 = e23.position();
          o14 = C9.x, s12 = C9.y;
          var S8 = e23.outerWidth() / 2, D7 = e23.outerHeight() / 2;
          va(h10, n14 = o14 - S8, a11 = s12 - D7, r11 = o14 + S8, i12 = s12 + D7);
        } else if (g9 && t18.includeEdges)
          if (c11 && !d12) {
            var P10 = e23.pstyle("curve-style").strValue;
            if (n14 = Math.min(v12.srcX, v12.midX, v12.tgtX), r11 = Math.max(v12.srcX, v12.midX, v12.tgtX), a11 = Math.min(v12.srcY, v12.midY, v12.tgtY), i12 = Math.max(v12.srcY, v12.midY, v12.tgtY), va(h10, n14 -= k10, a11 -= k10, r11 += k10, i12 += k10), "haystack" === P10) {
              var T9 = v12.haystackPts;
              if (T9 && 2 === T9.length) {
                if (n14 = T9[0].x, a11 = T9[0].y, n14 > (r11 = T9[1].x)) {
                  var M9 = n14;
                  n14 = r11, r11 = M9;
                }
                if (a11 > (i12 = T9[1].y)) {
                  var B8 = a11;
                  a11 = i12, i12 = B8;
                }
                va(h10, n14 - k10, a11 - k10, r11 + k10, i12 + k10);
              }
            } else if ("bezier" === P10 || "unbundled-bezier" === P10 || "segments" === P10 || "taxi" === P10) {
              var _7;
              switch (P10) {
                case "bezier":
                case "unbundled-bezier":
                  _7 = v12.bezierPts;
                  break;
                case "segments":
                case "taxi":
                  _7 = v12.linePts;
              }
              if (null != _7)
                for (var N8 = 0; N8 < _7.length; N8++) {
                  var I8 = _7[N8];
                  n14 = I8.x - k10, r11 = I8.x + k10, a11 = I8.y - k10, i12 = I8.y + k10, va(h10, n14, a11, r11, i12);
                }
            }
          } else {
            var z8 = e23.source().position(), L10 = e23.target().position();
            if ((n14 = z8.x) > (r11 = L10.x)) {
              var A10 = n14;
              n14 = r11, r11 = A10;
            }
            if ((a11 = z8.y) > (i12 = L10.y)) {
              var O9 = a11;
              a11 = i12, i12 = O9;
            }
            va(h10, n14 -= k10, a11 -= k10, r11 += k10, i12 += k10);
          }
        if (c11 && t18.includeEdges && g9 && (ba(h10, e23, "mid-source"), ba(h10, e23, "mid-target"), ba(h10, e23, "source"), ba(h10, e23, "target")), c11 && "yes" === e23.pstyle("ghost").value) {
          var R8 = e23.pstyle("ghost-offset-x").pfValue, V8 = e23.pstyle("ghost-offset-y").pfValue;
          va(h10, h10.x1 + R8, h10.y1 + V8, h10.x2 + R8, h10.y2 + V8);
        }
        var F9 = p10.bodyBounds = p10.bodyBounds || {};
        xt4(F9, h10), bt4(F9, y10), mt4(F9, 1), c11 && (n14 = h10.x1, r11 = h10.x2, a11 = h10.y1, i12 = h10.y2, va(h10, n14 - E10, a11 - E10, r11 + E10, i12 + E10));
        var q8 = p10.overlayBounds = p10.overlayBounds || {};
        xt4(q8, h10), bt4(q8, y10), mt4(q8, 1);
        var j9 = p10.labelBounds = p10.labelBounds || {};
        null != j9.all ? ((l12 = j9.all).x1 = 1 / 0, l12.y1 = 1 / 0, l12.x2 = -1 / 0, l12.y2 = -1 / 0, l12.w = 0, l12.h = 0) : j9.all = vt4(), c11 && t18.includeLabels && (t18.includeMainLabels && xa(h10, e23, null), g9 && (t18.includeSourceLabels && xa(h10, e23, "source"), t18.includeTargetLabels && xa(h10, e23, "target")));
      }
      return h10.x1 = ga(h10.x1), h10.y1 = ga(h10.y1), h10.x2 = ga(h10.x2), h10.y2 = ga(h10.y2), h10.w = ga(h10.x2 - h10.x1), h10.h = ga(h10.y2 - h10.y1), h10.w > 0 && h10.h > 0 && b11 && (bt4(h10, y10), mt4(h10, 1)), h10;
    }(e22, Ca), r10.bbCache = n13, r10.bbCachePosKey = o13) : n13 = r10.bbCache, !i11) {
      var c10 = e22.isNode();
      n13 = vt4(), (t17.includeNodes && c10 || t17.includeEdges && !c10) && (t17.includeOverlays ? ya(n13, r10.overlayBounds) : ya(n13, r10.bodyBounds)), t17.includeLabels && (t17.includeMainLabels && (!a10 || t17.includeSourceLabels && t17.includeTargetLabels) ? ya(n13, r10.labelBounds.all) : (t17.includeMainLabels && ya(n13, r10.labelBounds.mainRot), t17.includeSourceLabels && ya(n13, r10.labelBounds.sourceRot), t17.includeTargetLabels && ya(n13, r10.labelBounds.targetRot))), n13.w = n13.x2 - n13.x1, n13.h = n13.y2 - n13.y1;
    }
    return n13;
  };
  var Ca = { includeNodes: true, includeEdges: true, includeLabels: true, includeMainLabels: true, includeSourceLabels: true, includeTargetLabels: true, includeOverlays: true, includeUnderlays: true, useCache: true };
  var Sa = wa(Ca);
  var Da = ze(Ca);
  pa.boundingBox = function(e22) {
    var t17;
    if (1 !== this.length || null == this[0]._private.bbCache || this[0]._private.styleDirty || void 0 !== e22 && void 0 !== e22.useCache && true !== e22.useCache) {
      t17 = vt4();
      var n13 = Da(e22 = e22 || Ca), r10 = this;
      if (r10.cy().styleEnabled())
        for (var a10 = 0; a10 < r10.length; a10++) {
          var i11 = r10[a10], o13 = i11._private, s11 = Ea(i11), l11 = o13.bbCachePosKey === s11, u10 = n13.useCache && l11 && !o13.styleDirty;
          i11.recalculateRenderedStyle(u10);
        }
      this.updateCompoundBounds(!e22.useCache);
      for (var c10 = 0; c10 < r10.length; c10++) {
        var d12 = r10[c10];
        ya(t17, ka(d12, n13));
      }
    } else
      e22 = void 0 === e22 ? Ca : Da(e22), t17 = ka(this[0], e22);
    return t17.x1 = ga(t17.x1), t17.y1 = ga(t17.y1), t17.x2 = ga(t17.x2), t17.y2 = ga(t17.y2), t17.w = ga(t17.x2 - t17.x1), t17.h = ga(t17.y2 - t17.y1), t17;
  }, pa.dirtyBoundingBoxCache = function() {
    for (var e22 = 0; e22 < this.length; e22++) {
      var t17 = this[e22]._private;
      t17.bbCache = null, t17.bbCachePosKey = null, t17.bodyBounds = null, t17.overlayBounds = null, t17.labelBounds.all = null, t17.labelBounds.source = null, t17.labelBounds.target = null, t17.labelBounds.main = null, t17.labelBounds.sourceRot = null, t17.labelBounds.targetRot = null, t17.labelBounds.mainRot = null, t17.arrowBounds.source = null, t17.arrowBounds.target = null, t17.arrowBounds["mid-source"] = null, t17.arrowBounds["mid-target"] = null;
    }
    return this.emitAndNotify("bounds"), this;
  }, pa.boundingBoxAt = function(e22) {
    var t17 = this.nodes(), n13 = this.cy(), r10 = n13.hasCompoundNodes(), a10 = n13.collection();
    if (r10 && (a10 = t17.filter(function(e23) {
      return e23.isParent();
    }), t17 = t17.not(a10)), N6(e22)) {
      var i11 = e22;
      e22 = function() {
        return i11;
      };
    }
    n13.startBatch(), t17.forEach(function(t18, n14) {
      return t18._private.bbAtOldPos = e22(t18, n14);
    }).silentPositions(e22), r10 && (a10.dirtyCompoundBoundsCache(), a10.dirtyBoundingBoxCache(), a10.updateCompoundBounds(true));
    var o13 = function(e23) {
      return { x1: e23.x1, x2: e23.x2, w: e23.w, y1: e23.y1, y2: e23.y2, h: e23.h };
    }(this.boundingBox({ useCache: false }));
    return t17.silentPositions(function(e23) {
      return e23._private.bbAtOldPos;
    }), r10 && (a10.dirtyCompoundBoundsCache(), a10.dirtyBoundingBoxCache(), a10.updateCompoundBounds(true)), n13.endBatch(), o13;
  }, ha.boundingbox = ha.bb = ha.boundingBox, ha.renderedBoundingbox = ha.renderedBoundingBox;
  var Pa;
  var Ta;
  var Ma = pa;
  Pa = Ta = {};
  var Ba = function(e22) {
    e22.uppercaseName = H4(e22.name), e22.autoName = "auto" + e22.uppercaseName, e22.labelName = "label" + e22.uppercaseName, e22.outerName = "outer" + e22.uppercaseName, e22.uppercaseOuterName = H4(e22.outerName), Pa[e22.name] = function() {
      var t17 = this[0], n13 = t17._private, r10 = n13.cy._private.styleEnabled;
      if (t17) {
        if (r10) {
          if (t17.isParent())
            return t17.updateCompoundBounds(), n13[e22.autoName] || 0;
          var a10 = t17.pstyle(e22.name);
          return "label" === a10.strValue ? (t17.recalculateRenderedStyle(), n13.rstyle[e22.labelName] || 0) : a10.pfValue;
        }
        return 1;
      }
    }, Pa["outer" + e22.uppercaseName] = function() {
      var t17 = this[0], n13 = t17._private.cy._private.styleEnabled;
      if (t17)
        return n13 ? t17[e22.name]() + t17.pstyle("border-width").pfValue + 2 * t17.padding() : 1;
    }, Pa["rendered" + e22.uppercaseName] = function() {
      var t17 = this[0];
      if (t17)
        return t17[e22.name]() * this.cy().zoom();
    }, Pa["rendered" + e22.uppercaseOuterName] = function() {
      var t17 = this[0];
      if (t17)
        return t17[e22.outerName]() * this.cy().zoom();
    };
  };
  Ba({ name: "width" }), Ba({ name: "height" }), Ta.padding = function() {
    var e22 = this[0], t17 = e22._private;
    return e22.isParent() ? (e22.updateCompoundBounds(), void 0 !== t17.autoPadding ? t17.autoPadding : e22.pstyle("padding").pfValue) : e22.pstyle("padding").pfValue;
  }, Ta.paddedHeight = function() {
    var e22 = this[0];
    return e22.height() + 2 * e22.padding();
  }, Ta.paddedWidth = function() {
    var e22 = this[0];
    return e22.width() + 2 * e22.padding();
  };
  var _a = Ta;
  var Na = { controlPoints: { get: function(e22) {
    return e22.renderer().getControlPoints(e22);
  }, mult: true }, segmentPoints: { get: function(e22) {
    return e22.renderer().getSegmentPoints(e22);
  }, mult: true }, sourceEndpoint: { get: function(e22) {
    return e22.renderer().getSourceEndpoint(e22);
  } }, targetEndpoint: { get: function(e22) {
    return e22.renderer().getTargetEndpoint(e22);
  } }, midpoint: { get: function(e22) {
    return e22.renderer().getEdgeMidpoint(e22);
  } } };
  var Ia = Object.keys(Na).reduce(function(e22, t17) {
    var n13 = Na[t17], r10 = function(e23) {
      return "rendered" + e23[0].toUpperCase() + e23.substr(1);
    }(t17);
    return e22[t17] = function() {
      return function(e23, t18) {
        if (e23.isEdge())
          return t18(e23);
      }(this, n13.get);
    }, n13.mult ? e22[r10] = function() {
      return function(e23, t18) {
        if (e23.isEdge()) {
          var n14 = e23.cy(), r11 = n14.pan(), a10 = n14.zoom();
          return t18(e23).map(function(e24) {
            return at4(e24, a10, r11);
          });
        }
      }(this, n13.get);
    } : e22[r10] = function() {
      return function(e23, t18) {
        if (e23.isEdge()) {
          var n14 = e23.cy();
          return at4(t18(e23), n14.zoom(), n14.pan());
        }
      }(this, n13.get);
    }, e22;
  }, {});
  var za = J4({}, fa, Ma, _a, Ia);
  var La = function(e22, t17) {
    this.recycle(e22, t17);
  };
  function Aa() {
    return false;
  }
  function Oa() {
    return true;
  }
  La.prototype = { instanceString: function() {
    return "event";
  }, recycle: function(e22, t17) {
    if (this.isImmediatePropagationStopped = this.isPropagationStopped = this.isDefaultPrevented = Aa, null != e22 && e22.preventDefault ? (this.type = e22.type, this.isDefaultPrevented = e22.defaultPrevented ? Oa : Aa) : null != e22 && e22.type ? t17 = e22 : this.type = e22, null != t17 && (this.originalEvent = t17.originalEvent, this.type = null != t17.type ? t17.type : this.type, this.cy = t17.cy, this.target = t17.target, this.position = t17.position, this.renderedPosition = t17.renderedPosition, this.namespace = t17.namespace, this.layout = t17.layout), null != this.cy && null != this.position && null == this.renderedPosition) {
      var n13 = this.position, r10 = this.cy.zoom(), a10 = this.cy.pan();
      this.renderedPosition = { x: n13.x * r10 + a10.x, y: n13.y * r10 + a10.y };
    }
    this.timeStamp = e22 && e22.timeStamp || Date.now();
  }, preventDefault: function() {
    this.isDefaultPrevented = Oa;
    var e22 = this.originalEvent;
    e22 && e22.preventDefault && e22.preventDefault();
  }, stopPropagation: function() {
    this.isPropagationStopped = Oa;
    var e22 = this.originalEvent;
    e22 && e22.stopPropagation && e22.stopPropagation();
  }, stopImmediatePropagation: function() {
    this.isImmediatePropagationStopped = Oa, this.stopPropagation();
  }, isDefaultPrevented: Aa, isPropagationStopped: Aa, isImmediatePropagationStopped: Aa };
  var Ra = /^([^.]+)(\.(?:[^.]+))?$/;
  var Va = { qualifierCompare: function(e22, t17) {
    return e22 === t17;
  }, eventMatches: function() {
    return true;
  }, addEventFields: function() {
  }, callbackContext: function(e22) {
    return e22;
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
    for (var e22 = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : qa, t17 = arguments.length > 1 ? arguments[1] : void 0, n13 = 0; n13 < Fa.length; n13++) {
      var r10 = Fa[n13];
      this[r10] = e22[r10] || Va[r10];
    }
    this.context = t17 || this.context, this.listeners = [], this.emitting = 0;
  }
  var Ya = ja.prototype;
  var Xa = function(e22, t17, n13, r10, a10, i11, o13) {
    B4(r10) && (a10 = r10, r10 = null), o13 && (i11 = null == i11 ? o13 : J4({}, i11, o13));
    for (var s11 = _5(n13) ? n13 : n13.split(/\s+/), l11 = 0; l11 < s11.length; l11++) {
      var u10 = s11[l11];
      if (!F6(u10)) {
        var c10 = u10.match(Ra);
        if (c10) {
          if (false === t17(e22, u10, c10[1], c10[2] ? c10[2] : null, r10, a10, i11))
            break;
        }
      }
    }
  };
  var Wa = function(e22, t17) {
    return e22.addEventFields(e22.context, t17), new La(t17.type, t17);
  };
  var Ha = function(e22, t17, n13) {
    if ("event" !== T6(n13))
      if (N6(n13))
        t17(e22, Wa(e22, n13));
      else
        for (var r10 = _5(n13) ? n13 : n13.split(/\s+/), a10 = 0; a10 < r10.length; a10++) {
          var i11 = r10[a10];
          if (!F6(i11)) {
            var o13 = i11.match(Ra);
            if (o13) {
              var s11 = o13[1], l11 = o13[2] ? o13[2] : null;
              t17(e22, Wa(e22, { type: s11, namespace: l11, target: e22.context }));
            }
          }
        }
    else
      t17(e22, n13);
  };
  Ya.on = Ya.addListener = function(e22, t17, n13, r10, a10) {
    return Xa(this, function(e23, t18, n14, r11, a11, i11, o13) {
      B4(i11) && e23.listeners.push({ event: t18, callback: i11, type: n14, namespace: r11, qualifier: a11, conf: o13 });
    }, e22, t17, n13, r10, a10), this;
  }, Ya.one = function(e22, t17, n13, r10) {
    return this.on(e22, t17, n13, r10, { one: true });
  }, Ya.removeListener = Ya.off = function(e22, t17, n13, r10) {
    var a10 = this;
    0 !== this.emitting && (this.listeners = this.listeners.slice());
    for (var i11 = this.listeners, o13 = function(o14) {
      var s12 = i11[o14];
      Xa(a10, function(t18, n14, r11, a11, l11, u10) {
        if ((s12.type === r11 || "*" === e22) && (!a11 && ".*" !== s12.namespace || s12.namespace === a11) && (!l11 || t18.qualifierCompare(s12.qualifier, l11)) && (!u10 || s12.callback === u10))
          return i11.splice(o14, 1), false;
      }, e22, t17, n13, r10);
    }, s11 = i11.length - 1; s11 >= 0; s11--)
      o13(s11);
    return this;
  }, Ya.removeAllListeners = function() {
    return this.removeListener("*");
  }, Ya.emit = Ya.trigger = function(e22, t17, n13) {
    var r10 = this.listeners, a10 = r10.length;
    return this.emitting++, _5(t17) || (t17 = [t17]), Ha(this, function(e23, i11) {
      null != n13 && (r10 = [{ event: i11.event, type: i11.type, namespace: i11.namespace, callback: n13 }], a10 = r10.length);
      for (var o13 = function(n14) {
        var a11 = r10[n14];
        if (a11.type === i11.type && (!a11.namespace || a11.namespace === i11.namespace || ".*" === a11.namespace) && e23.eventMatches(e23.context, a11, i11)) {
          var o14 = [i11];
          null != t17 && function(e24, t18) {
            for (var n15 = 0; n15 < t18.length; n15++) {
              var r11 = t18[n15];
              e24.push(r11);
            }
          }(o14, t17), e23.beforeEmit(e23.context, a11, i11), a11.conf && a11.conf.one && (e23.listeners = e23.listeners.filter(function(e24) {
            return e24 !== a11;
          }));
          var s12 = e23.callbackContext(e23.context, a11, i11), l11 = a11.callback.apply(s12, o14);
          e23.afterEmit(e23.context, a11, i11), false === l11 && (i11.stopPropagation(), i11.preventDefault());
        }
      }, s11 = 0; s11 < a10; s11++)
        o13(s11);
      e23.bubble(e23.context) && !i11.isPropagationStopped() && e23.parent(e23.context).emit(i11, t17);
    }, e22), this.emitting--, this;
  };
  var Ka = { qualifierCompare: function(e22, t17) {
    return null == e22 || null == t17 ? null == e22 && null == t17 : e22.sameText(t17);
  }, eventMatches: function(e22, t17, n13) {
    var r10 = t17.qualifier;
    return null == r10 || e22 !== n13.target && A6(n13.target) && r10.matches(n13.target);
  }, addEventFields: function(e22, t17) {
    t17.cy = e22.cy(), t17.target = e22;
  }, callbackContext: function(e22, t17, n13) {
    return null != t17.qualifier ? n13.target : e22;
  }, beforeEmit: function(e22, t17) {
    t17.conf && t17.conf.once && t17.conf.onceCollection.removeListener(t17.event, t17.qualifier, t17.callback);
  }, bubble: function() {
    return true;
  }, parent: function(e22) {
    return e22.isChild() ? e22.parent() : e22.cy();
  } };
  var Ga = function(e22) {
    return M6(e22) ? new Kr(e22) : e22;
  };
  var Ua = { createEmitter: function() {
    for (var e22 = 0; e22 < this.length; e22++) {
      var t17 = this[e22], n13 = t17._private;
      n13.emitter || (n13.emitter = new ja(Ka, t17));
    }
    return this;
  }, emitter: function() {
    return this._private.emitter;
  }, on: function(e22, t17, n13) {
    for (var r10 = Ga(t17), a10 = 0; a10 < this.length; a10++) {
      this[a10].emitter().on(e22, r10, n13);
    }
    return this;
  }, removeListener: function(e22, t17, n13) {
    for (var r10 = Ga(t17), a10 = 0; a10 < this.length; a10++) {
      this[a10].emitter().removeListener(e22, r10, n13);
    }
    return this;
  }, removeAllListeners: function() {
    for (var e22 = 0; e22 < this.length; e22++) {
      this[e22].emitter().removeAllListeners();
    }
    return this;
  }, one: function(e22, t17, n13) {
    for (var r10 = Ga(t17), a10 = 0; a10 < this.length; a10++) {
      this[a10].emitter().one(e22, r10, n13);
    }
    return this;
  }, once: function(e22, t17, n13) {
    for (var r10 = Ga(t17), a10 = 0; a10 < this.length; a10++) {
      this[a10].emitter().on(e22, r10, n13, { once: true, onceCollection: this });
    }
  }, emit: function(e22, t17) {
    for (var n13 = 0; n13 < this.length; n13++) {
      this[n13].emitter().emit(e22, t17);
    }
    return this;
  }, emitAndNotify: function(e22, t17) {
    if (0 !== this.length)
      return this.cy().notify(e22, this), this.emit(e22, t17), this;
  } };
  ur3.eventAliasesOn(Ua);
  var Za = { nodes: function(e22) {
    return this.filter(function(e23) {
      return e23.isNode();
    }).filter(e22);
  }, edges: function(e22) {
    return this.filter(function(e23) {
      return e23.isEdge();
    }).filter(e22);
  }, byGroup: function() {
    for (var e22 = this.spawn(), t17 = this.spawn(), n13 = 0; n13 < this.length; n13++) {
      var r10 = this[n13];
      r10.isNode() ? e22.push(r10) : t17.push(r10);
    }
    return { nodes: e22, edges: t17 };
  }, filter: function(e22, t17) {
    if (void 0 === e22)
      return this;
    if (M6(e22) || L5(e22))
      return new Kr(e22).filter(this);
    if (B4(e22)) {
      for (var n13 = this.spawn(), r10 = this, a10 = 0; a10 < r10.length; a10++) {
        var i11 = r10[a10];
        (t17 ? e22.apply(t17, [i11, a10, r10]) : e22(i11, a10, r10)) && n13.push(i11);
      }
      return n13;
    }
    return this.spawn();
  }, not: function(e22) {
    if (e22) {
      M6(e22) && (e22 = this.filter(e22));
      for (var t17 = this.spawn(), n13 = 0; n13 < this.length; n13++) {
        var r10 = this[n13];
        e22.has(r10) || t17.push(r10);
      }
      return t17;
    }
    return this;
  }, absoluteComplement: function() {
    return this.cy().mutableElements().not(this);
  }, intersect: function(e22) {
    if (M6(e22)) {
      var t17 = e22;
      return this.filter(t17);
    }
    for (var n13 = this.spawn(), r10 = e22, a10 = this.length < e22.length, i11 = a10 ? this : r10, o13 = a10 ? r10 : this, s11 = 0; s11 < i11.length; s11++) {
      var l11 = i11[s11];
      o13.has(l11) && n13.push(l11);
    }
    return n13;
  }, xor: function(e22) {
    var t17 = this._private.cy;
    M6(e22) && (e22 = t17.$(e22));
    var n13 = this.spawn(), r10 = e22, a10 = function(e23, t18) {
      for (var r11 = 0; r11 < e23.length; r11++) {
        var a11 = e23[r11], i11 = a11._private.data.id;
        t18.hasElementWithId(i11) || n13.push(a11);
      }
    };
    return a10(this, r10), a10(r10, this), n13;
  }, diff: function(e22) {
    var t17 = this._private.cy;
    M6(e22) && (e22 = t17.$(e22));
    var n13 = this.spawn(), r10 = this.spawn(), a10 = this.spawn(), i11 = e22, o13 = function(e23, t18, n14) {
      for (var r11 = 0; r11 < e23.length; r11++) {
        var i12 = e23[r11], o14 = i12._private.data.id;
        t18.hasElementWithId(o14) ? a10.merge(i12) : n14.push(i12);
      }
    };
    return o13(this, i11, n13), o13(i11, this, r10), { left: n13, right: r10, both: a10 };
  }, add: function(e22) {
    var t17 = this._private.cy;
    if (!e22)
      return this;
    if (M6(e22)) {
      var n13 = e22;
      e22 = t17.mutableElements().filter(n13);
    }
    for (var r10 = this.spawnSelf(), a10 = 0; a10 < e22.length; a10++) {
      var i11 = e22[a10], o13 = !this.has(i11);
      o13 && r10.push(i11);
    }
    return r10;
  }, merge: function(e22) {
    var t17 = this._private, n13 = t17.cy;
    if (!e22)
      return this;
    if (e22 && M6(e22)) {
      var r10 = e22;
      e22 = n13.mutableElements().filter(r10);
    }
    for (var a10 = t17.map, i11 = 0; i11 < e22.length; i11++) {
      var o13 = e22[i11], s11 = o13._private.data.id;
      if (!a10.has(s11)) {
        var l11 = this.length++;
        this[l11] = o13, a10.set(s11, { ele: o13, index: l11 });
      }
    }
    return this;
  }, unmergeAt: function(e22) {
    var t17 = this[e22].id(), n13 = this._private.map;
    this[e22] = void 0, n13.delete(t17);
    var r10 = e22 === this.length - 1;
    if (this.length > 1 && !r10) {
      var a10 = this.length - 1, i11 = this[a10], o13 = i11._private.data.id;
      this[a10] = void 0, this[e22] = i11, n13.set(o13, { ele: i11, index: e22 });
    }
    return this.length--, this;
  }, unmergeOne: function(e22) {
    e22 = e22[0];
    var t17 = this._private, n13 = e22._private.data.id, r10 = t17.map.get(n13);
    if (!r10)
      return this;
    var a10 = r10.index;
    return this.unmergeAt(a10), this;
  }, unmerge: function(e22) {
    var t17 = this._private.cy;
    if (!e22)
      return this;
    if (e22 && M6(e22)) {
      var n13 = e22;
      e22 = t17.mutableElements().filter(n13);
    }
    for (var r10 = 0; r10 < e22.length; r10++)
      this.unmergeOne(e22[r10]);
    return this;
  }, unmergeBy: function(e22) {
    for (var t17 = this.length - 1; t17 >= 0; t17--) {
      e22(this[t17]) && this.unmergeAt(t17);
    }
    return this;
  }, map: function(e22, t17) {
    for (var n13 = [], r10 = this, a10 = 0; a10 < r10.length; a10++) {
      var i11 = r10[a10], o13 = t17 ? e22.apply(t17, [i11, a10, r10]) : e22(i11, a10, r10);
      n13.push(o13);
    }
    return n13;
  }, reduce: function(e22, t17) {
    for (var n13 = t17, r10 = this, a10 = 0; a10 < r10.length; a10++)
      n13 = e22(n13, r10[a10], a10, r10);
    return n13;
  }, max: function(e22, t17) {
    for (var n13, r10 = -1 / 0, a10 = this, i11 = 0; i11 < a10.length; i11++) {
      var o13 = a10[i11], s11 = t17 ? e22.apply(t17, [o13, i11, a10]) : e22(o13, i11, a10);
      s11 > r10 && (r10 = s11, n13 = o13);
    }
    return { value: r10, ele: n13 };
  }, min: function(e22, t17) {
    for (var n13, r10 = 1 / 0, a10 = this, i11 = 0; i11 < a10.length; i11++) {
      var o13 = a10[i11], s11 = t17 ? e22.apply(t17, [o13, i11, a10]) : e22(o13, i11, a10);
      s11 < r10 && (r10 = s11, n13 = o13);
    }
    return { value: r10, ele: n13 };
  } };
  var $a = Za;
  $a.u = $a["|"] = $a["+"] = $a.union = $a.or = $a.add, $a["\\"] = $a["!"] = $a["-"] = $a.difference = $a.relativeComplement = $a.subtract = $a.not, $a.n = $a["&"] = $a["."] = $a.and = $a.intersection = $a.intersect, $a["^"] = $a["(+)"] = $a["(-)"] = $a.symmetricDifference = $a.symdiff = $a.xor, $a.fnFilter = $a.filterFn = $a.stdFilter = $a.filter, $a.complement = $a.abscomp = $a.absoluteComplement;
  var Qa = function(e22, t17) {
    var n13 = e22.cy().hasCompoundNodes();
    function r10(e23) {
      var t18 = e23.pstyle("z-compound-depth");
      return "auto" === t18.value ? n13 ? e23.zDepth() : 0 : "bottom" === t18.value ? -1 : "top" === t18.value ? Ee : 0;
    }
    var a10 = r10(e22) - r10(t17);
    if (0 !== a10)
      return a10;
    function i11(e23) {
      return "auto" === e23.pstyle("z-index-compare").value && e23.isNode() ? 1 : 0;
    }
    var o13 = i11(e22) - i11(t17);
    if (0 !== o13)
      return o13;
    var s11 = e22.pstyle("z-index").value - t17.pstyle("z-index").value;
    return 0 !== s11 ? s11 : e22.poolIndex() - t17.poolIndex();
  };
  var Ja = { forEach: function(e22, t17) {
    if (B4(e22))
      for (var n13 = this.length, r10 = 0; r10 < n13; r10++) {
        var a10 = this[r10];
        if (false === (t17 ? e22.apply(t17, [a10, r10, this]) : e22(a10, r10, this)))
          break;
      }
    return this;
  }, toArray: function() {
    for (var e22 = [], t17 = 0; t17 < this.length; t17++)
      e22.push(this[t17]);
    return e22;
  }, slice: function(e22, t17) {
    var n13 = [], r10 = this.length;
    null == t17 && (t17 = r10), null == e22 && (e22 = 0), e22 < 0 && (e22 = r10 + e22), t17 < 0 && (t17 = r10 + t17);
    for (var a10 = e22; a10 >= 0 && a10 < t17 && a10 < r10; a10++)
      n13.push(this[a10]);
    return this.spawn(n13);
  }, size: function() {
    return this.length;
  }, eq: function(e22) {
    return this[e22] || this.spawn();
  }, first: function() {
    return this[0] || this.spawn();
  }, last: function() {
    return this[this.length - 1] || this.spawn();
  }, empty: function() {
    return 0 === this.length;
  }, nonempty: function() {
    return !this.empty();
  }, sort: function(e22) {
    if (!B4(e22))
      return this;
    var t17 = this.toArray().sort(e22);
    return this.spawn(t17);
  }, sortByZIndex: function() {
    return this.sort(Qa);
  }, zDepth: function() {
    var e22 = this[0];
    if (e22) {
      var t17 = e22._private;
      if ("nodes" === t17.group) {
        var n13 = t17.data.parent ? e22.parents().size() : 0;
        return e22.isParent() ? n13 : Ee - 1;
      }
      var r10 = t17.source, a10 = t17.target, i11 = r10.zDepth(), o13 = a10.zDepth();
      return Math.max(i11, o13, 0);
    }
  } };
  Ja.each = Ja.forEach;
  var ei;
  ei = "undefined", ("undefined" == typeof Symbol ? "undefined" : g6(Symbol)) != ei && g6(Symbol.iterator) != ei && (Ja[Symbol.iterator] = function() {
    var e22 = this, t17 = { value: void 0, done: false }, n13 = 0, r10 = this.length;
    return b6({ next: function() {
      return n13 < r10 ? t17.value = e22[n13++] : (t17.value = void 0, t17.done = true), t17;
    } }, Symbol.iterator, function() {
      return this;
    });
  });
  var ti = ze({ nodeDimensionsIncludeLabels: false });
  var ni = { layoutDimensions: function(e22) {
    var t17;
    if (e22 = ti(e22), this.takesUpSpace())
      if (e22.nodeDimensionsIncludeLabels) {
        var n13 = this.boundingBox();
        t17 = { w: n13.w, h: n13.h };
      } else
        t17 = { w: this.outerWidth(), h: this.outerHeight() };
    else
      t17 = { w: 0, h: 0 };
    return 0 !== t17.w && 0 !== t17.h || (t17.w = t17.h = 1), t17;
  }, layoutPositions: function(e22, t17, n13) {
    var r10 = this.nodes().filter(function(e23) {
      return !e23.isParent();
    }), a10 = this.cy(), i11 = t17.eles, o13 = function(e23) {
      return e23.id();
    }, s11 = j6(n13, o13);
    e22.emit({ type: "layoutstart", layout: e22 }), e22.animations = [];
    var l11 = t17.spacingFactor && 1 !== t17.spacingFactor, u10 = function() {
      if (!l11)
        return null;
      for (var e23 = vt4(), t18 = 0; t18 < r10.length; t18++) {
        var n14 = r10[t18], a11 = s11(n14, t18);
        yt4(e23, a11.x, a11.y);
      }
      return e23;
    }(), c10 = j6(function(e23, n14) {
      var r11 = s11(e23, n14);
      l11 && (r11 = function(e24, t18, n15) {
        var r12 = t18.x1 + t18.w / 2, a11 = t18.y1 + t18.h / 2;
        return { x: r12 + (n15.x - r12) * e24, y: a11 + (n15.y - a11) * e24 };
      }(Math.abs(t17.spacingFactor), u10, r11));
      return null != t17.transform && (r11 = t17.transform(e23, r11)), r11;
    }, o13);
    if (t17.animate) {
      for (var d12 = 0; d12 < r10.length; d12++) {
        var h10 = r10[d12], p10 = c10(h10, d12);
        if (null == t17.animateFilter || t17.animateFilter(h10, d12)) {
          var f11 = h10.animation({ position: p10, duration: t17.animationDuration, easing: t17.animationEasing });
          e22.animations.push(f11);
        } else
          h10.position(p10);
      }
      if (t17.fit) {
        var g9 = a10.animation({ fit: { boundingBox: i11.boundingBoxAt(c10), padding: t17.padding }, duration: t17.animationDuration, easing: t17.animationEasing });
        e22.animations.push(g9);
      } else if (void 0 !== t17.zoom && void 0 !== t17.pan) {
        var v12 = a10.animation({ zoom: t17.zoom, pan: t17.pan, duration: t17.animationDuration, easing: t17.animationEasing });
        e22.animations.push(v12);
      }
      e22.animations.forEach(function(e23) {
        return e23.play();
      }), e22.one("layoutready", t17.ready), e22.emit({ type: "layoutready", layout: e22 }), rr4.all(e22.animations.map(function(e23) {
        return e23.promise();
      })).then(function() {
        e22.one("layoutstop", t17.stop), e22.emit({ type: "layoutstop", layout: e22 });
      });
    } else
      r10.positions(c10), t17.fit && a10.fit(t17.eles, t17.padding), null != t17.zoom && a10.zoom(t17.zoom), t17.pan && a10.pan(t17.pan), e22.one("layoutready", t17.ready), e22.emit({ type: "layoutready", layout: e22 }), e22.one("layoutstop", t17.stop), e22.emit({ type: "layoutstop", layout: e22 });
    return this;
  }, layout: function(e22) {
    return this.cy().makeLayout(J4({}, e22, { eles: this }));
  } };
  function ri(e22, t17, n13) {
    var r10, a10 = n13._private, i11 = a10.styleCache = a10.styleCache || [];
    return null != (r10 = i11[e22]) ? r10 : r10 = i11[e22] = t17(n13);
  }
  function ai(e22, t17) {
    return e22 = ve(e22), function(n13) {
      return ri(e22, t17, n13);
    };
  }
  function ii(e22, t17) {
    e22 = ve(e22);
    var n13 = function(e23) {
      return t17.call(e23);
    };
    return function() {
      var t18 = this[0];
      if (t18)
        return ri(e22, n13, t18);
    };
  }
  ni.createLayout = ni.makeLayout = ni.layout;
  var oi = { recalculateRenderedStyle: function(e22) {
    var t17 = this.cy(), n13 = t17.renderer(), r10 = t17.styleEnabled();
    return n13 && r10 && n13.recalculateRenderedStyle(this, e22), this;
  }, dirtyStyleCache: function() {
    var e22, t17 = this.cy(), n13 = function(e23) {
      return e23._private.styleCache = null;
    };
    t17.hasCompoundNodes() ? ((e22 = this.spawnSelf().merge(this.descendants()).merge(this.parents())).merge(e22.connectedEdges()), e22.forEach(n13)) : this.forEach(function(e23) {
      n13(e23), e23.connectedEdges().forEach(n13);
    });
    return this;
  }, updateStyle: function(e22) {
    var t17 = this._private.cy;
    if (!t17.styleEnabled())
      return this;
    if (t17.batching())
      return t17._private.batchStyleEles.merge(this), this;
    var n13 = this;
    e22 = !(!e22 && void 0 !== e22), t17.hasCompoundNodes() && (n13 = this.spawnSelf().merge(this.descendants()).merge(this.parents()));
    var r10 = n13;
    return e22 ? r10.emitAndNotify("style") : r10.emit("style"), n13.forEach(function(e23) {
      return e23._private.styleDirty = true;
    }), this;
  }, cleanStyle: function() {
    var e22 = this.cy();
    if (e22.styleEnabled())
      for (var t17 = 0; t17 < this.length; t17++) {
        var n13 = this[t17];
        n13._private.styleDirty && (n13._private.styleDirty = false, e22.style().apply(n13));
      }
  }, parsedStyle: function(e22) {
    var t17 = !(arguments.length > 1 && void 0 !== arguments[1]) || arguments[1], n13 = this[0], r10 = n13.cy();
    if (r10.styleEnabled() && n13) {
      this.cleanStyle();
      var a10 = n13._private.style[e22];
      return null != a10 ? a10 : t17 ? r10.style().getDefaultProperty(e22) : null;
    }
  }, numericStyle: function(e22) {
    var t17 = this[0];
    if (t17.cy().styleEnabled() && t17) {
      var n13 = t17.pstyle(e22);
      return void 0 !== n13.pfValue ? n13.pfValue : n13.value;
    }
  }, numericStyleUnits: function(e22) {
    var t17 = this[0];
    if (t17.cy().styleEnabled())
      return t17 ? t17.pstyle(e22).units : void 0;
  }, renderedStyle: function(e22) {
    var t17 = this.cy();
    if (!t17.styleEnabled())
      return this;
    var n13 = this[0];
    return n13 ? t17.style().getRenderedStyle(n13, e22) : void 0;
  }, style: function(e22, t17) {
    var n13 = this.cy();
    if (!n13.styleEnabled())
      return this;
    var r10 = n13.style();
    if (N6(e22)) {
      var a10 = e22;
      r10.applyBypass(this, a10, false), this.emitAndNotify("style");
    } else if (M6(e22)) {
      if (void 0 === t17) {
        var i11 = this[0];
        return i11 ? r10.getStylePropertyValue(i11, e22) : void 0;
      }
      r10.applyBypass(this, e22, t17, false), this.emitAndNotify("style");
    } else if (void 0 === e22) {
      var o13 = this[0];
      return o13 ? r10.getRawStyle(o13) : void 0;
    }
    return this;
  }, removeStyle: function(e22) {
    var t17 = this.cy();
    if (!t17.styleEnabled())
      return this;
    var n13 = t17.style(), r10 = this;
    if (void 0 === e22)
      for (var a10 = 0; a10 < r10.length; a10++) {
        var i11 = r10[a10];
        n13.removeAllBypasses(i11, false);
      }
    else {
      e22 = e22.split(/\s+/);
      for (var o13 = 0; o13 < r10.length; o13++) {
        var s11 = r10[o13];
        n13.removeBypasses(s11, e22, false);
      }
    }
    return this.emitAndNotify("style"), this;
  }, show: function() {
    return this.css("display", "element"), this;
  }, hide: function() {
    return this.css("display", "none"), this;
  }, effectiveOpacity: function() {
    var e22 = this.cy();
    if (!e22.styleEnabled())
      return 1;
    var t17 = e22.hasCompoundNodes(), n13 = this[0];
    if (n13) {
      var r10 = n13._private, a10 = n13.pstyle("opacity").value;
      if (!t17)
        return a10;
      var i11 = r10.data.parent ? n13.parents() : null;
      if (i11)
        for (var o13 = 0; o13 < i11.length; o13++) {
          a10 *= i11[o13].pstyle("opacity").value;
        }
      return a10;
    }
  }, transparent: function() {
    if (!this.cy().styleEnabled())
      return false;
    var e22 = this[0], t17 = e22.cy().hasCompoundNodes();
    return e22 ? t17 ? 0 === e22.effectiveOpacity() : 0 === e22.pstyle("opacity").value : void 0;
  }, backgrounding: function() {
    return !!this.cy().styleEnabled() && !!this[0]._private.backgrounding;
  } };
  function si(e22, t17) {
    var n13 = e22._private.data.parent ? e22.parents() : null;
    if (n13)
      for (var r10 = 0; r10 < n13.length; r10++) {
        if (!t17(n13[r10]))
          return false;
      }
    return true;
  }
  function li(e22) {
    var t17 = e22.ok, n13 = e22.edgeOkViaNode || e22.ok, r10 = e22.parentOk || e22.ok;
    return function() {
      var e23 = this.cy();
      if (!e23.styleEnabled())
        return true;
      var a10 = this[0], i11 = e23.hasCompoundNodes();
      if (a10) {
        var o13 = a10._private;
        if (!t17(a10))
          return false;
        if (a10.isNode())
          return !i11 || si(a10, r10);
        var s11 = o13.source, l11 = o13.target;
        return n13(s11) && (!i11 || si(s11, n13)) && (s11 === l11 || n13(l11) && (!i11 || si(l11, n13)));
      }
    };
  }
  var ui = ai("eleTakesUpSpace", function(e22) {
    return "element" === e22.pstyle("display").value && 0 !== e22.width() && (!e22.isNode() || 0 !== e22.height());
  });
  oi.takesUpSpace = ii("takesUpSpace", li({ ok: ui }));
  var ci = ai("eleInteractive", function(e22) {
    return "yes" === e22.pstyle("events").value && "visible" === e22.pstyle("visibility").value && ui(e22);
  });
  var di = ai("parentInteractive", function(e22) {
    return "visible" === e22.pstyle("visibility").value && ui(e22);
  });
  oi.interactive = ii("interactive", li({ ok: ci, parentOk: di, edgeOkViaNode: ui })), oi.noninteractive = function() {
    var e22 = this[0];
    if (e22)
      return !e22.interactive();
  };
  var hi = ai("eleVisible", function(e22) {
    return "visible" === e22.pstyle("visibility").value && 0 !== e22.pstyle("opacity").pfValue && ui(e22);
  });
  var pi = ui;
  oi.visible = ii("visible", li({ ok: hi, edgeOkViaNode: pi })), oi.hidden = function() {
    var e22 = this[0];
    if (e22)
      return !e22.visible();
  }, oi.isBundledBezier = ii("isBundledBezier", function() {
    return !!this.cy().styleEnabled() && (!this.removed() && "bezier" === this.pstyle("curve-style").value && this.takesUpSpace());
  }), oi.bypass = oi.css = oi.style, oi.renderedCss = oi.renderedStyle, oi.removeBypass = oi.removeCss = oi.removeStyle, oi.pstyle = oi.parsedStyle;
  var fi = {};
  function gi(e22) {
    return function() {
      var t17 = arguments, n13 = [];
      if (2 === t17.length) {
        var r10 = t17[0], a10 = t17[1];
        this.on(e22.event, r10, a10);
      } else if (1 === t17.length && B4(t17[0])) {
        var i11 = t17[0];
        this.on(e22.event, i11);
      } else if (0 === t17.length || 1 === t17.length && _5(t17[0])) {
        for (var o13 = 1 === t17.length ? t17[0] : null, s11 = 0; s11 < this.length; s11++) {
          var l11 = this[s11], u10 = !e22.ableField || l11._private[e22.ableField], c10 = l11._private[e22.field] != e22.value;
          if (e22.overrideAble) {
            var d12 = e22.overrideAble(l11);
            if (void 0 !== d12 && (u10 = d12, !d12))
              return this;
          }
          u10 && (l11._private[e22.field] = e22.value, c10 && n13.push(l11));
        }
        var h10 = this.spawn(n13);
        h10.updateStyle(), h10.emit(e22.event), o13 && h10.emit(o13);
      }
      return this;
    };
  }
  function vi(e22) {
    fi[e22.field] = function() {
      var t17 = this[0];
      if (t17) {
        if (e22.overrideField) {
          var n13 = e22.overrideField(t17);
          if (void 0 !== n13)
            return n13;
        }
        return t17._private[e22.field];
      }
    }, fi[e22.on] = gi({ event: e22.on, field: e22.field, ableField: e22.ableField, overrideAble: e22.overrideAble, value: true }), fi[e22.off] = gi({ event: e22.off, field: e22.field, ableField: e22.ableField, overrideAble: e22.overrideAble, value: false });
  }
  vi({ field: "locked", overrideField: function(e22) {
    return !!e22.cy().autolock() || void 0;
  }, on: "lock", off: "unlock" }), vi({ field: "grabbable", overrideField: function(e22) {
    return !e22.cy().autoungrabify() && !e22.pannable() && void 0;
  }, on: "grabify", off: "ungrabify" }), vi({ field: "selected", ableField: "selectable", overrideAble: function(e22) {
    return !e22.cy().autounselectify() && void 0;
  }, on: "select", off: "unselect" }), vi({ field: "selectable", overrideField: function(e22) {
    return !e22.cy().autounselectify() && void 0;
  }, on: "selectify", off: "unselectify" }), fi.deselect = fi.unselect, fi.grabbed = function() {
    var e22 = this[0];
    if (e22)
      return e22._private.grabbed;
  }, vi({ field: "active", on: "activate", off: "unactivate" }), vi({ field: "pannable", on: "panify", off: "unpanify" }), fi.inactive = function() {
    var e22 = this[0];
    if (e22)
      return !e22._private.active;
  };
  var yi = {};
  var mi = function(e22) {
    return function(t17) {
      for (var n13 = [], r10 = 0; r10 < this.length; r10++) {
        var a10 = this[r10];
        if (a10.isNode()) {
          for (var i11 = false, o13 = a10.connectedEdges(), s11 = 0; s11 < o13.length; s11++) {
            var l11 = o13[s11], u10 = l11.source(), c10 = l11.target();
            if (e22.noIncomingEdges && c10 === a10 && u10 !== a10 || e22.noOutgoingEdges && u10 === a10 && c10 !== a10) {
              i11 = true;
              break;
            }
          }
          i11 || n13.push(a10);
        }
      }
      return this.spawn(n13, true).filter(t17);
    };
  };
  var bi = function(e22) {
    return function(t17) {
      for (var n13 = [], r10 = 0; r10 < this.length; r10++) {
        var a10 = this[r10];
        if (a10.isNode())
          for (var i11 = a10.connectedEdges(), o13 = 0; o13 < i11.length; o13++) {
            var s11 = i11[o13], l11 = s11.source(), u10 = s11.target();
            e22.outgoing && l11 === a10 ? (n13.push(s11), n13.push(u10)) : e22.incoming && u10 === a10 && (n13.push(s11), n13.push(l11));
          }
      }
      return this.spawn(n13, true).filter(t17);
    };
  };
  var xi = function(e22) {
    return function(t17) {
      for (var n13 = this, r10 = [], a10 = {}; ; ) {
        var i11 = e22.outgoing ? n13.outgoers() : n13.incomers();
        if (0 === i11.length)
          break;
        for (var o13 = false, s11 = 0; s11 < i11.length; s11++) {
          var l11 = i11[s11], u10 = l11.id();
          a10[u10] || (a10[u10] = true, r10.push(l11), o13 = true);
        }
        if (!o13)
          break;
        n13 = i11;
      }
      return this.spawn(r10, true).filter(t17);
    };
  };
  function wi(e22) {
    return function(t17) {
      for (var n13 = [], r10 = 0; r10 < this.length; r10++) {
        var a10 = this[r10]._private[e22.attr];
        a10 && n13.push(a10);
      }
      return this.spawn(n13, true).filter(t17);
    };
  }
  function Ei(e22) {
    return function(t17) {
      var n13 = [], r10 = this._private.cy, a10 = e22 || {};
      M6(t17) && (t17 = r10.$(t17));
      for (var i11 = 0; i11 < t17.length; i11++)
        for (var o13 = t17[i11]._private.edges, s11 = 0; s11 < o13.length; s11++) {
          var l11 = o13[s11], u10 = l11._private.data, c10 = this.hasElementWithId(u10.source) && t17.hasElementWithId(u10.target), d12 = t17.hasElementWithId(u10.source) && this.hasElementWithId(u10.target);
          if (c10 || d12) {
            if (a10.thisIsSrc || a10.thisIsTgt) {
              if (a10.thisIsSrc && !c10)
                continue;
              if (a10.thisIsTgt && !d12)
                continue;
            }
            n13.push(l11);
          }
        }
      return this.spawn(n13, true);
    };
  }
  function ki(e22) {
    return e22 = J4({}, { codirected: false }, e22), function(t17) {
      for (var n13 = [], r10 = this.edges(), a10 = e22, i11 = 0; i11 < r10.length; i11++)
        for (var o13 = r10[i11]._private, s11 = o13.source, l11 = s11._private.data.id, u10 = o13.data.target, c10 = s11._private.edges, d12 = 0; d12 < c10.length; d12++) {
          var h10 = c10[d12], p10 = h10._private.data, f11 = p10.target, g9 = p10.source, v12 = f11 === u10 && g9 === l11, y10 = l11 === f11 && u10 === g9;
          (a10.codirected && v12 || !a10.codirected && (v12 || y10)) && n13.push(h10);
        }
      return this.spawn(n13, true).filter(t17);
    };
  }
  yi.clearTraversalCache = function() {
    for (var e22 = 0; e22 < this.length; e22++)
      this[e22]._private.traversalCache = null;
  }, J4(yi, { roots: mi({ noIncomingEdges: true }), leaves: mi({ noOutgoingEdges: true }), outgoers: Qr(bi({ outgoing: true }), "outgoers"), successors: xi({ outgoing: true }), incomers: Qr(bi({ incoming: true }), "incomers"), predecessors: xi({ incoming: true }) }), J4(yi, { neighborhood: Qr(function(e22) {
    for (var t17 = [], n13 = this.nodes(), r10 = 0; r10 < n13.length; r10++)
      for (var a10 = n13[r10], i11 = a10.connectedEdges(), o13 = 0; o13 < i11.length; o13++) {
        var s11 = i11[o13], l11 = s11.source(), u10 = s11.target(), c10 = a10 === l11 ? u10 : l11;
        c10.length > 0 && t17.push(c10[0]), t17.push(s11[0]);
      }
    return this.spawn(t17, true).filter(e22);
  }, "neighborhood"), closedNeighborhood: function(e22) {
    return this.neighborhood().add(this).filter(e22);
  }, openNeighborhood: function(e22) {
    return this.neighborhood(e22);
  } }), yi.neighbourhood = yi.neighborhood, yi.closedNeighbourhood = yi.closedNeighborhood, yi.openNeighbourhood = yi.openNeighborhood, J4(yi, { source: Qr(function(e22) {
    var t17, n13 = this[0];
    return n13 && (t17 = n13._private.source || n13.cy().collection()), t17 && e22 ? t17.filter(e22) : t17;
  }, "source"), target: Qr(function(e22) {
    var t17, n13 = this[0];
    return n13 && (t17 = n13._private.target || n13.cy().collection()), t17 && e22 ? t17.filter(e22) : t17;
  }, "target"), sources: wi({ attr: "source" }), targets: wi({ attr: "target" }) }), J4(yi, { edgesWith: Qr(Ei(), "edgesWith"), edgesTo: Qr(Ei({ thisIsSrc: true }), "edgesTo") }), J4(yi, { connectedEdges: Qr(function(e22) {
    for (var t17 = [], n13 = 0; n13 < this.length; n13++) {
      var r10 = this[n13];
      if (r10.isNode())
        for (var a10 = r10._private.edges, i11 = 0; i11 < a10.length; i11++) {
          var o13 = a10[i11];
          t17.push(o13);
        }
    }
    return this.spawn(t17, true).filter(e22);
  }, "connectedEdges"), connectedNodes: Qr(function(e22) {
    for (var t17 = [], n13 = 0; n13 < this.length; n13++) {
      var r10 = this[n13];
      r10.isEdge() && (t17.push(r10.source()[0]), t17.push(r10.target()[0]));
    }
    return this.spawn(t17, true).filter(e22);
  }, "connectedNodes"), parallelEdges: Qr(ki(), "parallelEdges"), codirectedEdges: Qr(ki({ codirected: true }), "codirectedEdges") }), J4(yi, { components: function(e22) {
    var t17 = this, n13 = t17.cy(), r10 = n13.collection(), a10 = null == e22 ? t17.nodes() : e22.nodes(), i11 = [];
    null != e22 && a10.empty() && (a10 = e22.sources());
    var o13 = function(e23, t18) {
      r10.merge(e23), a10.unmerge(e23), t18.merge(e23);
    };
    if (a10.empty())
      return t17.spawn();
    var s11 = function() {
      var e23 = n13.collection();
      i11.push(e23);
      var r11 = a10[0];
      o13(r11, e23), t17.bfs({ directed: false, roots: r11, visit: function(t18) {
        return o13(t18, e23);
      } }), e23.forEach(function(n14) {
        n14.connectedEdges().forEach(function(n15) {
          t17.has(n15) && e23.has(n15.source()) && e23.has(n15.target()) && e23.merge(n15);
        });
      });
    };
    do {
      s11();
    } while (a10.length > 0);
    return i11;
  }, component: function() {
    var e22 = this[0];
    return e22.cy().mutableElements().components(e22)[0];
  } }), yi.componentsOf = yi.components;
  var Ci = function(e22, t17) {
    var n13 = arguments.length > 2 && void 0 !== arguments[2] && arguments[2], r10 = arguments.length > 3 && void 0 !== arguments[3] && arguments[3];
    if (void 0 !== e22) {
      var a10 = new Ve(), i11 = false;
      if (t17) {
        if (t17.length > 0 && N6(t17[0]) && !A6(t17[0])) {
          i11 = true;
          for (var o13 = [], s11 = new qe(), l11 = 0, u10 = t17.length; l11 < u10; l11++) {
            var c10 = t17[l11];
            null == c10.data && (c10.data = {});
            var d12 = c10.data;
            if (null == d12.id)
              d12.id = _e();
            else if (e22.hasElementWithId(d12.id) || s11.has(d12.id))
              continue;
            var h10 = new je(e22, c10, false);
            o13.push(h10), s11.add(d12.id);
          }
          t17 = o13;
        }
      } else
        t17 = [];
      this.length = 0;
      for (var p10 = 0, f11 = t17.length; p10 < f11; p10++) {
        var g9 = t17[p10][0];
        if (null != g9) {
          var v12 = g9._private.data.id;
          n13 && a10.has(v12) || (n13 && a10.set(v12, { index: this.length, ele: g9 }), this[this.length] = g9, this.length++);
        }
      }
      this._private = { eles: this, cy: e22, get map() {
        return null == this.lazyMap && this.rebuildMap(), this.lazyMap;
      }, set map(e23) {
        this.lazyMap = e23;
      }, rebuildMap: function() {
        for (var e23 = this.lazyMap = new Ve(), t18 = this.eles, n14 = 0; n14 < t18.length; n14++) {
          var r11 = t18[n14];
          e23.set(r11.id(), { index: n14, ele: r11 });
        }
      } }, n13 && (this._private.map = a10), i11 && !r10 && this.restore();
    } else
      Pe("A collection must have a reference to the core");
  };
  var Si = je.prototype = Ci.prototype = Object.create(Array.prototype);
  Si.instanceString = function() {
    return "collection";
  }, Si.spawn = function(e22, t17) {
    return new Ci(this.cy(), e22, t17);
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
  }, Si.hasElementWithId = function(e22) {
    return e22 = "" + e22, this._private.map.has(e22);
  }, Si.getElementById = function(e22) {
    e22 = "" + e22;
    var t17 = this._private.cy, n13 = this._private.map.get(e22);
    return n13 ? n13.ele : new Ci(t17);
  }, Si.$id = Si.getElementById, Si.poolIndex = function() {
    var e22 = this._private.cy._private.elements, t17 = this[0]._private.data.id;
    return e22._private.map.get(t17).index;
  }, Si.indexOf = function(e22) {
    var t17 = e22[0]._private.data.id;
    return this._private.map.get(t17).index;
  }, Si.indexOfId = function(e22) {
    return e22 = "" + e22, this._private.map.get(e22).index;
  }, Si.json = function(e22) {
    var t17 = this.element(), n13 = this.cy();
    if (null == t17 && e22)
      return this;
    if (null != t17) {
      var r10 = t17._private;
      if (N6(e22)) {
        if (n13.startBatch(), e22.data) {
          t17.data(e22.data);
          var a10 = r10.data;
          if (t17.isEdge()) {
            var i11 = false, o13 = {}, s11 = e22.data.source, l11 = e22.data.target;
            null != s11 && s11 != a10.source && (o13.source = "" + s11, i11 = true), null != l11 && l11 != a10.target && (o13.target = "" + l11, i11 = true), i11 && (t17 = t17.move(o13));
          } else {
            var u10 = "parent" in e22.data, c10 = e22.data.parent;
            !u10 || null == c10 && null == a10.parent || c10 == a10.parent || (void 0 === c10 && (c10 = null), null != c10 && (c10 = "" + c10), t17 = t17.move({ parent: c10 }));
          }
        }
        e22.position && t17.position(e22.position);
        var d12 = function(n14, a11, i12) {
          var o14 = e22[n14];
          null != o14 && o14 !== r10[n14] && (o14 ? t17[a11]() : t17[i12]());
        };
        return d12("removed", "remove", "restore"), d12("selected", "select", "unselect"), d12("selectable", "selectify", "unselectify"), d12("locked", "lock", "unlock"), d12("grabbable", "grabify", "ungrabify"), d12("pannable", "panify", "unpanify"), null != e22.classes && t17.classes(e22.classes), n13.endBatch(), this;
      }
      if (void 0 === e22) {
        var h10 = { data: Be(r10.data), position: Be(r10.position), group: r10.group, removed: r10.removed, selected: r10.selected, selectable: r10.selectable, locked: r10.locked, grabbable: r10.grabbable, pannable: r10.pannable, classes: null };
        h10.classes = "";
        var p10 = 0;
        return r10.classes.forEach(function(e23) {
          return h10.classes += 0 == p10++ ? e23 : " " + e23;
        }), h10;
      }
    }
  }, Si.jsons = function() {
    for (var e22 = [], t17 = 0; t17 < this.length; t17++) {
      var n13 = this[t17].json();
      e22.push(n13);
    }
    return e22;
  }, Si.clone = function() {
    for (var e22 = this.cy(), t17 = [], n13 = 0; n13 < this.length; n13++) {
      var r10 = this[n13].json(), a10 = new je(e22, r10, false);
      t17.push(a10);
    }
    return new Ci(e22, t17);
  }, Si.copy = Si.clone, Si.restore = function() {
    for (var e22, t17, n13 = !(arguments.length > 0 && void 0 !== arguments[0]) || arguments[0], r10 = !(arguments.length > 1 && void 0 !== arguments[1]) || arguments[1], a10 = this, i11 = a10.cy(), o13 = i11._private, s11 = [], l11 = [], u10 = 0, c10 = a10.length; u10 < c10; u10++) {
      var d12 = a10[u10];
      r10 && !d12.removed() || (d12.isNode() ? s11.push(d12) : l11.push(d12));
    }
    e22 = s11.concat(l11);
    var h10 = function() {
      e22.splice(t17, 1), t17--;
    };
    for (t17 = 0; t17 < e22.length; t17++) {
      var p10 = e22[t17], f11 = p10._private, g9 = f11.data;
      if (p10.clearTraversalCache(), r10 || f11.removed)
        if (void 0 === g9.id)
          g9.id = _e();
        else if (I6(g9.id))
          g9.id = "" + g9.id;
        else {
          if (F6(g9.id) || !M6(g9.id)) {
            Pe("Can not create element with invalid string ID `" + g9.id + "`"), h10();
            continue;
          }
          if (i11.hasElementWithId(g9.id)) {
            Pe("Can not create second element with ID `" + g9.id + "`"), h10();
            continue;
          }
        }
      else
        ;
      var v12 = g9.id;
      if (p10.isNode()) {
        var y10 = f11.position;
        null == y10.x && (y10.x = 0), null == y10.y && (y10.y = 0);
      }
      if (p10.isEdge()) {
        for (var m12 = p10, b11 = ["source", "target"], x11 = b11.length, w10 = false, E10 = 0; E10 < x11; E10++) {
          var k10 = b11[E10], C9 = g9[k10];
          I6(C9) && (C9 = g9[k10] = "" + g9[k10]), null == C9 || "" === C9 ? (Pe("Can not create edge `" + v12 + "` with unspecified " + k10), w10 = true) : i11.hasElementWithId(C9) || (Pe("Can not create edge `" + v12 + "` with nonexistant " + k10 + " `" + C9 + "`"), w10 = true);
        }
        if (w10) {
          h10();
          continue;
        }
        var S8 = i11.getElementById(g9.source), D7 = i11.getElementById(g9.target);
        S8.same(D7) ? S8._private.edges.push(m12) : (S8._private.edges.push(m12), D7._private.edges.push(m12)), m12._private.source = S8, m12._private.target = D7;
      }
      f11.map = new Ve(), f11.map.set(v12, { ele: p10, index: 0 }), f11.removed = false, r10 && i11.addToPool(p10);
    }
    for (var P10 = 0; P10 < s11.length; P10++) {
      var T9 = s11[P10], B8 = T9._private.data;
      I6(B8.parent) && (B8.parent = "" + B8.parent);
      var _7 = B8.parent;
      if (null != _7 || T9._private.parent) {
        var N8 = T9._private.parent ? i11.collection().merge(T9._private.parent) : i11.getElementById(_7);
        if (N8.empty())
          B8.parent = void 0;
        else if (N8[0].removed())
          Me("Node added with missing parent, reference to parent removed"), B8.parent = void 0, T9._private.parent = null;
        else {
          for (var z8 = false, L10 = N8; !L10.empty(); ) {
            if (T9.same(L10)) {
              z8 = true, B8.parent = void 0;
              break;
            }
            L10 = L10.parent();
          }
          z8 || (N8[0]._private.children.push(T9), T9._private.parent = N8[0], o13.hasCompoundNodes = true);
        }
      }
    }
    if (e22.length > 0) {
      for (var A10 = e22.length === a10.length ? a10 : new Ci(i11, e22), O9 = 0; O9 < A10.length; O9++) {
        var R8 = A10[O9];
        R8.isNode() || (R8.parallelEdges().clearTraversalCache(), R8.source().clearTraversalCache(), R8.target().clearTraversalCache());
      }
      (o13.hasCompoundNodes ? i11.collection().merge(A10).merge(A10.connectedNodes()).merge(A10.parent()) : A10).dirtyCompoundBoundsCache().dirtyBoundingBoxCache().updateStyle(n13), n13 ? A10.emitAndNotify("add") : r10 && A10.emit("add");
    }
    return a10;
  }, Si.removed = function() {
    var e22 = this[0];
    return e22 && e22._private.removed;
  }, Si.inside = function() {
    var e22 = this[0];
    return e22 && !e22._private.removed;
  }, Si.remove = function() {
    var e22 = !(arguments.length > 0 && void 0 !== arguments[0]) || arguments[0], t17 = !(arguments.length > 1 && void 0 !== arguments[1]) || arguments[1], n13 = this, r10 = [], a10 = {}, i11 = n13._private.cy;
    function o13(e23) {
      var n14 = a10[e23.id()];
      t17 && e23.removed() || n14 || (a10[e23.id()] = true, e23.isNode() ? (r10.push(e23), function(e24) {
        for (var t18 = e24._private.edges, n15 = 0; n15 < t18.length; n15++)
          o13(t18[n15]);
      }(e23), function(e24) {
        for (var t18 = e24._private.children, n15 = 0; n15 < t18.length; n15++)
          o13(t18[n15]);
      }(e23)) : r10.unshift(e23));
    }
    for (var s11 = 0, l11 = n13.length; s11 < l11; s11++) {
      o13(n13[s11]);
    }
    function u10(e23, t18) {
      var n14 = e23._private.edges;
      Le(n14, t18), e23.clearTraversalCache();
    }
    function c10(e23) {
      e23.clearTraversalCache();
    }
    var d12 = [];
    function h10(e23, t18) {
      t18 = t18[0];
      var n14 = (e23 = e23[0])._private.children, r11 = e23.id();
      Le(n14, t18), t18._private.parent = null, d12.ids[r11] || (d12.ids[r11] = true, d12.push(e23));
    }
    d12.ids = {}, n13.dirtyCompoundBoundsCache(), t17 && i11.removeFromPool(r10);
    for (var p10 = 0; p10 < r10.length; p10++) {
      var f11 = r10[p10];
      if (f11.isEdge()) {
        var g9 = f11.source()[0], v12 = f11.target()[0];
        u10(g9, f11), u10(v12, f11);
        for (var y10 = f11.parallelEdges(), m12 = 0; m12 < y10.length; m12++) {
          var b11 = y10[m12];
          c10(b11), b11.isBundledBezier() && b11.dirtyBoundingBoxCache();
        }
      } else {
        var x11 = f11.parent();
        0 !== x11.length && h10(x11, f11);
      }
      t17 && (f11._private.removed = true);
    }
    var w10 = i11._private.elements;
    i11._private.hasCompoundNodes = false;
    for (var E10 = 0; E10 < w10.length; E10++) {
      if (w10[E10].isParent()) {
        i11._private.hasCompoundNodes = true;
        break;
      }
    }
    var k10 = new Ci(this.cy(), r10);
    k10.size() > 0 && (e22 ? k10.emitAndNotify("remove") : t17 && k10.emit("remove"));
    for (var C9 = 0; C9 < d12.length; C9++) {
      var S8 = d12[C9];
      t17 && S8.removed() || S8.updateStyle();
    }
    return k10;
  }, Si.move = function(e22) {
    var t17 = this._private.cy, n13 = this, r10 = false, a10 = false, i11 = function(e23) {
      return null == e23 ? e23 : "" + e23;
    };
    if (void 0 !== e22.source || void 0 !== e22.target) {
      var o13 = i11(e22.source), s11 = i11(e22.target), l11 = null != o13 && t17.hasElementWithId(o13), u10 = null != s11 && t17.hasElementWithId(s11);
      (l11 || u10) && (t17.batch(function() {
        n13.remove(r10, a10), n13.emitAndNotify("moveout");
        for (var e23 = 0; e23 < n13.length; e23++) {
          var t18 = n13[e23], i12 = t18._private.data;
          t18.isEdge() && (l11 && (i12.source = o13), u10 && (i12.target = s11));
        }
        n13.restore(r10, a10);
      }), n13.emitAndNotify("move"));
    } else if (void 0 !== e22.parent) {
      var c10 = i11(e22.parent);
      if (null === c10 || t17.hasElementWithId(c10)) {
        var d12 = null === c10 ? void 0 : c10;
        t17.batch(function() {
          var e23 = n13.remove(r10, a10);
          e23.emitAndNotify("moveout");
          for (var t18 = 0; t18 < n13.length; t18++) {
            var i12 = n13[t18], o14 = i12._private.data;
            i12.isNode() && (o14.parent = d12);
          }
          e23.restore(r10, a10);
        }), n13.emitAndNotify("move");
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
    var e22 = this[0];
    if (e22)
      return e22._private.group;
  } }, Ja, ni, oi, fi, yi].forEach(function(e22) {
    J4(Si, e22);
  });
  var Di = { add: function(e22) {
    var t17, n13 = this;
    if (L5(e22)) {
      var r10 = e22;
      if (r10._private.cy === n13)
        t17 = r10.restore();
      else {
        for (var a10 = [], i11 = 0; i11 < r10.length; i11++) {
          var o13 = r10[i11];
          a10.push(o13.json());
        }
        t17 = new Ci(n13, a10);
      }
    } else if (_5(e22)) {
      t17 = new Ci(n13, e22);
    } else if (N6(e22) && (_5(e22.nodes) || _5(e22.edges))) {
      for (var s11 = e22, l11 = [], u10 = ["nodes", "edges"], c10 = 0, d12 = u10.length; c10 < d12; c10++) {
        var h10 = u10[c10], p10 = s11[h10];
        if (_5(p10))
          for (var f11 = 0, g9 = p10.length; f11 < g9; f11++) {
            var v12 = J4({ group: h10 }, p10[f11]);
            l11.push(v12);
          }
      }
      t17 = new Ci(n13, l11);
    } else {
      t17 = new je(n13, e22).collection();
    }
    return t17;
  }, remove: function(e22) {
    if (L5(e22))
      ;
    else if (M6(e22)) {
      var t17 = e22;
      e22 = this.$(t17);
    }
    return e22.remove();
  } };
  function Pi(e22, t17, n13, r10) {
    var a10 = 4, i11 = 1e-7, o13 = 10, s11 = 11, l11 = 1 / (s11 - 1), u10 = "undefined" != typeof Float32Array;
    if (4 !== arguments.length)
      return false;
    for (var c10 = 0; c10 < 4; ++c10)
      if ("number" != typeof arguments[c10] || isNaN(arguments[c10]) || !isFinite(arguments[c10]))
        return false;
    e22 = Math.min(e22, 1), n13 = Math.min(n13, 1), e22 = Math.max(e22, 0), n13 = Math.max(n13, 0);
    var d12 = u10 ? new Float32Array(s11) : new Array(s11);
    function h10(e23, t18) {
      return 1 - 3 * t18 + 3 * e23;
    }
    function p10(e23, t18) {
      return 3 * t18 - 6 * e23;
    }
    function f11(e23) {
      return 3 * e23;
    }
    function g9(e23, t18, n14) {
      return ((h10(t18, n14) * e23 + p10(t18, n14)) * e23 + f11(t18)) * e23;
    }
    function v12(e23, t18, n14) {
      return 3 * h10(t18, n14) * e23 * e23 + 2 * p10(t18, n14) * e23 + f11(t18);
    }
    function y10(t18) {
      for (var r11 = 0, u11 = 1, c11 = s11 - 1; u11 !== c11 && d12[u11] <= t18; ++u11)
        r11 += l11;
      --u11;
      var h11 = r11 + (t18 - d12[u11]) / (d12[u11 + 1] - d12[u11]) * l11, p11 = v12(h11, e22, n13);
      return p11 >= 1e-3 ? function(t19, r12) {
        for (var i12 = 0; i12 < a10; ++i12) {
          var o14 = v12(r12, e22, n13);
          if (0 === o14)
            return r12;
          r12 -= (g9(r12, e22, n13) - t19) / o14;
        }
        return r12;
      }(t18, h11) : 0 === p11 ? h11 : function(t19, r12, a11) {
        var s12, l12, u12 = 0;
        do {
          (s12 = g9(l12 = r12 + (a11 - r12) / 2, e22, n13) - t19) > 0 ? a11 = l12 : r12 = l12;
        } while (Math.abs(s12) > i11 && ++u12 < o13);
        return l12;
      }(t18, r11, r11 + l11);
    }
    var m12 = false;
    function b11() {
      m12 = true, e22 === t17 && n13 === r10 || function() {
        for (var t18 = 0; t18 < s11; ++t18)
          d12[t18] = g9(t18 * l11, e22, n13);
      }();
    }
    var x11 = function(a11) {
      return m12 || b11(), e22 === t17 && n13 === r10 ? a11 : 0 === a11 ? 0 : 1 === a11 ? 1 : g9(y10(a11), t17, r10);
    };
    x11.getControlPoints = function() {
      return [{ x: e22, y: t17 }, { x: n13, y: r10 }];
    };
    var w10 = "generateBezier(" + [e22, t17, n13, r10] + ")";
    return x11.toString = function() {
      return w10;
    }, x11;
  }
  var Ti = function() {
    function e22(e23) {
      return -e23.tension * e23.x - e23.friction * e23.v;
    }
    function t17(t18, n14, r10) {
      var a10 = { x: t18.x + r10.dx * n14, v: t18.v + r10.dv * n14, tension: t18.tension, friction: t18.friction };
      return { dx: a10.v, dv: e22(a10) };
    }
    function n13(n14, r10) {
      var a10 = { dx: n14.v, dv: e22(n14) }, i11 = t17(n14, 0.5 * r10, a10), o13 = t17(n14, 0.5 * r10, i11), s11 = t17(n14, r10, o13), l11 = 1 / 6 * (a10.dx + 2 * (i11.dx + o13.dx) + s11.dx), u10 = 1 / 6 * (a10.dv + 2 * (i11.dv + o13.dv) + s11.dv);
      return n14.x = n14.x + l11 * r10, n14.v = n14.v + u10 * r10, n14;
    }
    return function e23(t18, r10, a10) {
      var i11, o13, s11, l11 = { x: -1, v: 0, tension: null, friction: null }, u10 = [0], c10 = 0, d12 = 1e-4;
      for (t18 = parseFloat(t18) || 500, r10 = parseFloat(r10) || 20, a10 = a10 || null, l11.tension = t18, l11.friction = r10, o13 = (i11 = null !== a10) ? (c10 = e23(t18, r10)) / a10 * 0.016 : 0.016; s11 = n13(s11 || l11, o13), u10.push(1 + s11.x), c10 += 16, Math.abs(s11.x) > d12 && Math.abs(s11.v) > d12; )
        ;
      return i11 ? function(e24) {
        return u10[e24 * (u10.length - 1) | 0];
      } : c10;
    };
  }();
  var Mi = function(e22, t17, n13, r10) {
    var a10 = Pi(e22, t17, n13, r10);
    return function(e23, t18, n14) {
      return e23 + (t18 - e23) * a10(n14);
    };
  };
  var Bi = { linear: function(e22, t17, n13) {
    return e22 + (t17 - e22) * n13;
  }, ease: Mi(0.25, 0.1, 0.25, 1), "ease-in": Mi(0.42, 0, 1, 1), "ease-out": Mi(0, 0, 0.58, 1), "ease-in-out": Mi(0.42, 0, 0.58, 1), "ease-in-sine": Mi(0.47, 0, 0.745, 0.715), "ease-out-sine": Mi(0.39, 0.575, 0.565, 1), "ease-in-out-sine": Mi(0.445, 0.05, 0.55, 0.95), "ease-in-quad": Mi(0.55, 0.085, 0.68, 0.53), "ease-out-quad": Mi(0.25, 0.46, 0.45, 0.94), "ease-in-out-quad": Mi(0.455, 0.03, 0.515, 0.955), "ease-in-cubic": Mi(0.55, 0.055, 0.675, 0.19), "ease-out-cubic": Mi(0.215, 0.61, 0.355, 1), "ease-in-out-cubic": Mi(0.645, 0.045, 0.355, 1), "ease-in-quart": Mi(0.895, 0.03, 0.685, 0.22), "ease-out-quart": Mi(0.165, 0.84, 0.44, 1), "ease-in-out-quart": Mi(0.77, 0, 0.175, 1), "ease-in-quint": Mi(0.755, 0.05, 0.855, 0.06), "ease-out-quint": Mi(0.23, 1, 0.32, 1), "ease-in-out-quint": Mi(0.86, 0, 0.07, 1), "ease-in-expo": Mi(0.95, 0.05, 0.795, 0.035), "ease-out-expo": Mi(0.19, 1, 0.22, 1), "ease-in-out-expo": Mi(1, 0, 0, 1), "ease-in-circ": Mi(0.6, 0.04, 0.98, 0.335), "ease-out-circ": Mi(0.075, 0.82, 0.165, 1), "ease-in-out-circ": Mi(0.785, 0.135, 0.15, 0.86), spring: function(e22, t17, n13) {
    if (0 === n13)
      return Bi.linear;
    var r10 = Ti(e22, t17, n13);
    return function(e23, t18, n14) {
      return e23 + (t18 - e23) * r10(n14);
    };
  }, "cubic-bezier": Mi };
  function _i(e22, t17, n13, r10, a10) {
    if (1 === r10)
      return n13;
    if (t17 === n13)
      return n13;
    var i11 = a10(t17, n13, r10);
    return null == e22 || ((e22.roundValue || e22.color) && (i11 = Math.round(i11)), void 0 !== e22.min && (i11 = Math.max(i11, e22.min)), void 0 !== e22.max && (i11 = Math.min(i11, e22.max))), i11;
  }
  function Ni(e22, t17) {
    return null != e22.pfValue || null != e22.value ? null == e22.pfValue || null != t17 && "%" === t17.type.units ? e22.value : e22.pfValue : e22;
  }
  function Ii(e22, t17, n13, r10, a10) {
    var i11 = null != a10 ? a10.type : null;
    n13 < 0 ? n13 = 0 : n13 > 1 && (n13 = 1);
    var o13 = Ni(e22, a10), s11 = Ni(t17, a10);
    if (I6(o13) && I6(s11))
      return _i(i11, o13, s11, n13, r10);
    if (_5(o13) && _5(s11)) {
      for (var l11 = [], u10 = 0; u10 < s11.length; u10++) {
        var c10 = o13[u10], d12 = s11[u10];
        if (null != c10 && null != d12) {
          var h10 = _i(i11, c10, d12, n13, r10);
          l11.push(h10);
        } else
          l11.push(d12);
      }
      return l11;
    }
  }
  function zi(e22, t17, n13, r10) {
    var a10 = !r10, i11 = e22._private, o13 = t17._private, s11 = o13.easing, l11 = o13.startTime, u10 = (r10 ? e22 : e22.cy()).style();
    if (!o13.easingImpl)
      if (null == s11)
        o13.easingImpl = Bi.linear;
      else {
        var c10, d12, h10;
        if (M6(s11))
          c10 = u10.parse("transition-timing-function", s11).value;
        else
          c10 = s11;
        M6(c10) ? (d12 = c10, h10 = []) : (d12 = c10[1], h10 = c10.slice(2).map(function(e23) {
          return +e23;
        })), h10.length > 0 ? ("spring" === d12 && h10.push(o13.duration), o13.easingImpl = Bi[d12].apply(null, h10)) : o13.easingImpl = Bi[d12];
      }
    var p10, f11 = o13.easingImpl;
    if (p10 = 0 === o13.duration ? 1 : (n13 - l11) / o13.duration, o13.applying && (p10 = o13.progress), p10 < 0 ? p10 = 0 : p10 > 1 && (p10 = 1), null == o13.delay) {
      var g9 = o13.startPosition, v12 = o13.position;
      if (v12 && a10 && !e22.locked()) {
        var y10 = {};
        Li(g9.x, v12.x) && (y10.x = Ii(g9.x, v12.x, p10, f11)), Li(g9.y, v12.y) && (y10.y = Ii(g9.y, v12.y, p10, f11)), e22.position(y10);
      }
      var m12 = o13.startPan, b11 = o13.pan, x11 = i11.pan, w10 = null != b11 && r10;
      w10 && (Li(m12.x, b11.x) && (x11.x = Ii(m12.x, b11.x, p10, f11)), Li(m12.y, b11.y) && (x11.y = Ii(m12.y, b11.y, p10, f11)), e22.emit("pan"));
      var E10 = o13.startZoom, k10 = o13.zoom, C9 = null != k10 && r10;
      C9 && (Li(E10, k10) && (i11.zoom = gt4(i11.minZoom, Ii(E10, k10, p10, f11), i11.maxZoom)), e22.emit("zoom")), (w10 || C9) && e22.emit("viewport");
      var S8 = o13.style;
      if (S8 && S8.length > 0 && a10) {
        for (var D7 = 0; D7 < S8.length; D7++) {
          var P10 = S8[D7], T9 = P10.name, B8 = P10, _7 = o13.startStyle[T9], N8 = Ii(_7, B8, p10, f11, u10.properties[_7.name]);
          u10.overrideBypass(e22, T9, N8);
        }
        e22.emit("style");
      }
    }
    return o13.progress = p10, p10;
  }
  function Li(e22, t17) {
    return null != e22 && null != t17 && (!(!I6(e22) || !I6(t17)) || !(!e22 || !t17));
  }
  function Ai(e22, t17, n13, r10) {
    var a10 = t17._private;
    a10.started = true, a10.startTime = n13 - a10.progress * a10.duration;
  }
  function Oi(e22, t17) {
    var n13 = t17._private.aniEles, r10 = [];
    function a10(t18, n14) {
      var a11 = t18._private, i12 = a11.animation.current, o14 = a11.animation.queue, s12 = false;
      if (0 === i12.length) {
        var l12 = o14.shift();
        l12 && i12.push(l12);
      }
      for (var u10 = function(e23) {
        for (var t19 = e23.length - 1; t19 >= 0; t19--) {
          (0, e23[t19])();
        }
        e23.splice(0, e23.length);
      }, c10 = i12.length - 1; c10 >= 0; c10--) {
        var d12 = i12[c10], h10 = d12._private;
        h10.stopped ? (i12.splice(c10, 1), h10.hooked = false, h10.playing = false, h10.started = false, u10(h10.frames)) : (h10.playing || h10.applying) && (h10.playing && h10.applying && (h10.applying = false), h10.started || Ai(0, d12, e22), zi(t18, d12, e22, n14), h10.applying && (h10.applying = false), u10(h10.frames), null != h10.step && h10.step(e22), d12.completed() && (i12.splice(c10, 1), h10.hooked = false, h10.playing = false, h10.started = false, u10(h10.completes)), s12 = true);
      }
      return n14 || 0 !== i12.length || 0 !== o14.length || r10.push(t18), s12;
    }
    for (var i11 = false, o13 = 0; o13 < n13.length; o13++) {
      var s11 = a10(n13[o13]);
      i11 = i11 || s11;
    }
    var l11 = a10(t17, true);
    (i11 || l11) && (n13.length > 0 ? t17.notify("draw", n13) : t17.notify("draw")), n13.unmerge(r10), t17.emit("step");
  }
  var Ri = { animate: ur3.animate(), animation: ur3.animation(), animated: ur3.animated(), clearQueue: ur3.clearQueue(), delay: ur3.delay(), delayAnimation: ur3.delayAnimation(), stop: ur3.stop(), addToAnimationPool: function(e22) {
    this.styleEnabled() && this._private.aniEles.merge(e22);
  }, stopAnimationLoop: function() {
    this._private.animationsRunning = false;
  }, startAnimationLoop: function() {
    var e22 = this;
    if (e22._private.animationsRunning = true, e22.styleEnabled()) {
      var t17 = e22.renderer();
      t17 && t17.beforeRender ? t17.beforeRender(function(t18, n13) {
        Oi(n13, e22);
      }, t17.beforeRenderPriorities.animations) : function t18() {
        e22._private.animationsRunning && se(function(n13) {
          Oi(n13, e22), t18();
        });
      }();
    }
  } };
  var Vi = { qualifierCompare: function(e22, t17) {
    return null == e22 || null == t17 ? null == e22 && null == t17 : e22.sameText(t17);
  }, eventMatches: function(e22, t17, n13) {
    var r10 = t17.qualifier;
    return null == r10 || e22 !== n13.target && A6(n13.target) && r10.matches(n13.target);
  }, addEventFields: function(e22, t17) {
    t17.cy = e22, t17.target = e22;
  }, callbackContext: function(e22, t17, n13) {
    return null != t17.qualifier ? n13.target : e22;
  } };
  var Fi = function(e22) {
    return M6(e22) ? new Kr(e22) : e22;
  };
  var qi = { createEmitter: function() {
    var e22 = this._private;
    return e22.emitter || (e22.emitter = new ja(Vi, this)), this;
  }, emitter: function() {
    return this._private.emitter;
  }, on: function(e22, t17, n13) {
    return this.emitter().on(e22, Fi(t17), n13), this;
  }, removeListener: function(e22, t17, n13) {
    return this.emitter().removeListener(e22, Fi(t17), n13), this;
  }, removeAllListeners: function() {
    return this.emitter().removeAllListeners(), this;
  }, one: function(e22, t17, n13) {
    return this.emitter().one(e22, Fi(t17), n13), this;
  }, once: function(e22, t17, n13) {
    return this.emitter().one(e22, Fi(t17), n13), this;
  }, emit: function(e22, t17) {
    return this.emitter().emit(e22, t17), this;
  }, emitAndNotify: function(e22, t17) {
    return this.emit(e22), this.notify(e22, t17), this;
  } };
  ur3.eventAliasesOn(qi);
  var ji = { png: function(e22) {
    return e22 = e22 || {}, this._private.renderer.png(e22);
  }, jpg: function(e22) {
    var t17 = this._private.renderer;
    return (e22 = e22 || {}).bg = e22.bg || "#fff", t17.jpg(e22);
  } };
  ji.jpeg = ji.jpg;
  var Yi = { layout: function(e22) {
    var t17 = this;
    if (null != e22)
      if (null != e22.name) {
        var n13 = e22.name, r10 = t17.extension("layout", n13);
        if (null != r10) {
          var a10;
          a10 = M6(e22.eles) ? t17.$(e22.eles) : null != e22.eles ? e22.eles : t17.$();
          var i11 = new r10(J4({}, e22, { cy: t17, eles: a10 }));
          return i11;
        }
        Pe("No such layout `" + n13 + "` found.  Did you forget to import it and `cytoscape.use()` it?");
      } else
        Pe("A `name` must be specified to make a layout");
    else
      Pe("Layout options must be specified to make a layout");
  } };
  Yi.createLayout = Yi.makeLayout = Yi.layout;
  var Xi = { notify: function(e22, t17) {
    var n13 = this._private;
    if (this.batching()) {
      n13.batchNotifications = n13.batchNotifications || {};
      var r10 = n13.batchNotifications[e22] = n13.batchNotifications[e22] || this.collection();
      null != t17 && r10.merge(t17);
    } else if (n13.notificationsEnabled) {
      var a10 = this.renderer();
      !this.destroyed() && a10 && a10.notify(e22, t17);
    }
  }, notifications: function(e22) {
    var t17 = this._private;
    return void 0 === e22 ? t17.notificationsEnabled : (t17.notificationsEnabled = !!e22, this);
  }, noNotifications: function(e22) {
    this.notifications(false), e22(), this.notifications(true);
  }, batching: function() {
    return this._private.batchCount > 0;
  }, startBatch: function() {
    var e22 = this._private;
    return null == e22.batchCount && (e22.batchCount = 0), 0 === e22.batchCount && (e22.batchStyleEles = this.collection(), e22.batchNotifications = {}), e22.batchCount++, this;
  }, endBatch: function() {
    var e22 = this._private;
    if (0 === e22.batchCount)
      return this;
    if (e22.batchCount--, 0 === e22.batchCount) {
      e22.batchStyleEles.updateStyle();
      var t17 = this.renderer();
      Object.keys(e22.batchNotifications).forEach(function(n13) {
        var r10 = e22.batchNotifications[n13];
        r10.empty() ? t17.notify(n13) : t17.notify(n13, r10);
      });
    }
    return this;
  }, batch: function(e22) {
    return this.startBatch(), e22(), this.endBatch(), this;
  }, batchData: function(e22) {
    var t17 = this;
    return this.batch(function() {
      for (var n13 = Object.keys(e22), r10 = 0; r10 < n13.length; r10++) {
        var a10 = n13[r10], i11 = e22[a10];
        t17.getElementById(a10).data(i11);
      }
    });
  } };
  var Wi = ze({ hideEdgesOnViewport: false, textureOnViewport: false, motionBlur: false, motionBlurOpacity: 0.05, pixelRatio: void 0, desktopTapThreshold: 4, touchTapThreshold: 8, wheelSensitivity: 1, debug: false, showFps: false });
  var Hi = { renderTo: function(e22, t17, n13, r10) {
    return this._private.renderer.renderTo(e22, t17, n13, r10), this;
  }, renderer: function() {
    return this._private.renderer;
  }, forceRender: function() {
    return this.notify("draw"), this;
  }, resize: function() {
    return this.invalidateSize(), this.emitAndNotify("resize"), this;
  }, initRenderer: function(e22) {
    var t17 = this, n13 = t17.extension("renderer", e22.name);
    if (null != n13) {
      void 0 !== e22.wheelSensitivity && Me("You have set a custom wheel sensitivity.  This will make your app zoom unnaturally when using mainstream mice.  You should change this value from the default only if you can guarantee that all your users will use the same hardware and OS configuration as your current machine.");
      var r10 = Wi(e22);
      r10.cy = t17, t17._private.renderer = new n13(r10), this.notify("init");
    } else
      Pe("Can not initialise: No such renderer `".concat(e22.name, "` found. Did you forget to import it and `cytoscape.use()` it?"));
  }, destroyRenderer: function() {
    var e22 = this;
    e22.notify("destroy");
    var t17 = e22.container();
    if (t17)
      for (t17._cyreg = null; t17.childNodes.length > 0; )
        t17.removeChild(t17.childNodes[0]);
    e22._private.renderer = null, e22.mutableElements().forEach(function(e23) {
      var t18 = e23._private;
      t18.rscratch = {}, t18.rstyle = {}, t18.animation.current = [], t18.animation.queue = [];
    });
  }, onRender: function(e22) {
    return this.on("render", e22);
  }, offRender: function(e22) {
    return this.off("render", e22);
  } };
  Hi.invalidateDimensions = Hi.resize;
  var Ki = { collection: function(e22, t17) {
    return M6(e22) ? this.$(e22) : L5(e22) ? e22.collection() : _5(e22) ? (t17 || (t17 = {}), new Ci(this, e22, t17.unique, t17.removed)) : new Ci(this);
  }, nodes: function(e22) {
    var t17 = this.$(function(e23) {
      return e23.isNode();
    });
    return e22 ? t17.filter(e22) : t17;
  }, edges: function(e22) {
    var t17 = this.$(function(e23) {
      return e23.isEdge();
    });
    return e22 ? t17.filter(e22) : t17;
  }, $: function(e22) {
    var t17 = this._private.elements;
    return e22 ? t17.filter(e22) : t17.spawnSelf();
  }, mutableElements: function() {
    return this._private.elements;
  } };
  Ki.elements = Ki.filter = Ki.$;
  var Gi = {};
  var Ui = "t";
  Gi.apply = function(e22) {
    for (var t17 = this, n13 = t17._private.cy.collection(), r10 = 0; r10 < e22.length; r10++) {
      var a10 = e22[r10], i11 = t17.getContextMeta(a10);
      if (!i11.empty) {
        var o13 = t17.getContextStyle(i11), s11 = t17.applyContextStyle(i11, o13, a10);
        a10._private.appliedInitStyle ? t17.updateTransitions(a10, s11.diffProps) : a10._private.appliedInitStyle = true, t17.updateStyleHints(a10) && n13.push(a10);
      }
    }
    return n13;
  }, Gi.getPropertiesDiff = function(e22, t17) {
    var n13 = this, r10 = n13._private.propDiffs = n13._private.propDiffs || {}, a10 = e22 + "-" + t17, i11 = r10[a10];
    if (i11)
      return i11;
    for (var o13 = [], s11 = {}, l11 = 0; l11 < n13.length; l11++) {
      var u10 = n13[l11], c10 = e22[l11] === Ui, d12 = t17[l11] === Ui, h10 = c10 !== d12, p10 = u10.mappedProperties.length > 0;
      if (h10 || d12 && p10) {
        var f11 = void 0;
        h10 && p10 || h10 ? f11 = u10.properties : p10 && (f11 = u10.mappedProperties);
        for (var g9 = 0; g9 < f11.length; g9++) {
          for (var v12 = f11[g9], y10 = v12.name, m12 = false, b11 = l11 + 1; b11 < n13.length; b11++) {
            var x11 = n13[b11];
            if (t17[b11] === Ui && (m12 = null != x11.properties[v12.name]))
              break;
          }
          s11[y10] || m12 || (s11[y10] = true, o13.push(y10));
        }
      }
    }
    return r10[a10] = o13, o13;
  }, Gi.getContextMeta = function(e22) {
    for (var t17, n13 = this, r10 = "", a10 = e22._private.styleCxtKey || "", i11 = 0; i11 < n13.length; i11++) {
      var o13 = n13[i11];
      r10 += o13.selector && o13.selector.matches(e22) ? Ui : "f";
    }
    return t17 = n13.getPropertiesDiff(a10, r10), e22._private.styleCxtKey = r10, { key: r10, diffPropNames: t17, empty: 0 === t17.length };
  }, Gi.getContextStyle = function(e22) {
    var t17 = e22.key, n13 = this._private.contextStyles = this._private.contextStyles || {};
    if (n13[t17])
      return n13[t17];
    for (var r10 = { _private: { key: t17 } }, a10 = 0; a10 < this.length; a10++) {
      var i11 = this[a10];
      if (t17[a10] === Ui)
        for (var o13 = 0; o13 < i11.properties.length; o13++) {
          var s11 = i11.properties[o13];
          r10[s11.name] = s11;
        }
    }
    return n13[t17] = r10, r10;
  }, Gi.applyContextStyle = function(e22, t17, n13) {
    for (var r10 = e22.diffPropNames, a10 = {}, i11 = this.types, o13 = 0; o13 < r10.length; o13++) {
      var s11 = r10[o13], l11 = t17[s11], u10 = n13.pstyle(s11);
      if (!l11) {
        if (!u10)
          continue;
        l11 = u10.bypass ? { name: s11, deleteBypassed: true } : { name: s11, delete: true };
      }
      if (u10 !== l11) {
        if (l11.mapped === i11.fn && null != u10 && null != u10.mapping && u10.mapping.value === l11.value) {
          var c10 = u10.mapping;
          if ((c10.fnValue = l11.value(n13)) === c10.prevFnValue)
            continue;
        }
        var d12 = a10[s11] = { prev: u10 };
        this.applyParsedProperty(n13, l11), d12.next = n13.pstyle(s11), d12.next && d12.next.bypass && (d12.next = d12.next.bypassed);
      }
    }
    return { diffProps: a10 };
  }, Gi.updateStyleHints = function(e22) {
    var t17 = e22._private, n13 = this, r10 = n13.propertyGroupNames, a10 = n13.propertyGroupKeys, i11 = function(e23, t18, r11) {
      return n13.getPropertiesHash(e23, t18, r11);
    }, o13 = t17.styleKey;
    if (e22.removed())
      return false;
    var s11 = "nodes" === t17.group, l11 = e22._private.style;
    r10 = Object.keys(l11);
    for (var u10 = 0; u10 < a10.length; u10++) {
      var c10 = a10[u10];
      t17.styleKeys[c10] = [ue, ce];
    }
    for (var d12, h10 = function(e23, n14) {
      return t17.styleKeys[n14][0] = he(e23, t17.styleKeys[n14][0]);
    }, p10 = function(e23, n14) {
      return t17.styleKeys[n14][1] = pe(e23, t17.styleKeys[n14][1]);
    }, f11 = function(e23, t18) {
      h10(e23, t18), p10(e23, t18);
    }, g9 = function(e23, t18) {
      for (var n14 = 0; n14 < e23.length; n14++) {
        var r11 = e23.charCodeAt(n14);
        h10(r11, t18), p10(r11, t18);
      }
    }, v12 = 0; v12 < r10.length; v12++) {
      var y10 = r10[v12], m12 = l11[y10];
      if (null != m12) {
        var b11 = this.properties[y10], x11 = b11.type, w10 = b11.groupKey, E10 = void 0;
        null != b11.hashOverride ? E10 = b11.hashOverride(e22, m12) : null != m12.pfValue && (E10 = m12.pfValue);
        var k10 = null == b11.enums ? m12.value : null, C9 = null != E10, S8 = C9 || null != k10, D7 = m12.units;
        if (x11.number && S8 && !x11.multiple)
          f11(-128 < (d12 = C9 ? E10 : k10) && d12 < 128 && Math.floor(d12) !== d12 ? 2e9 - (1024 * d12 | 0) : d12, w10), C9 || null == D7 || g9(D7, w10);
        else
          g9(m12.strValue, w10);
      }
    }
    for (var P10, T9, M9 = [ue, ce], B8 = 0; B8 < a10.length; B8++) {
      var _7 = a10[B8], N8 = t17.styleKeys[_7];
      M9[0] = he(N8[0], M9[0]), M9[1] = pe(N8[1], M9[1]);
    }
    t17.styleKey = (P10 = M9[0], T9 = M9[1], 2097152 * P10 + T9);
    var I8 = t17.styleKeys;
    t17.labelDimsKey = fe(I8.labelDimensions);
    var z8 = i11(e22, ["label"], I8.labelDimensions);
    if (t17.labelKey = fe(z8), t17.labelStyleKey = fe(ge(I8.commonLabel, z8)), !s11) {
      var L10 = i11(e22, ["source-label"], I8.labelDimensions);
      t17.sourceLabelKey = fe(L10), t17.sourceLabelStyleKey = fe(ge(I8.commonLabel, L10));
      var A10 = i11(e22, ["target-label"], I8.labelDimensions);
      t17.targetLabelKey = fe(A10), t17.targetLabelStyleKey = fe(ge(I8.commonLabel, A10));
    }
    if (s11) {
      var O9 = t17.styleKeys, R8 = O9.nodeBody, V8 = O9.nodeBorder, F9 = O9.backgroundImage, q8 = O9.compound, j9 = O9.pie, Y6 = [R8, V8, F9, q8, j9].filter(function(e23) {
        return null != e23;
      }).reduce(ge, [ue, ce]);
      t17.nodeKey = fe(Y6), t17.hasPie = null != j9 && j9[0] !== ue && j9[1] !== ce;
    }
    return o13 !== t17.styleKey;
  }, Gi.clearStyleHints = function(e22) {
    var t17 = e22._private;
    t17.styleCxtKey = "", t17.styleKeys = {}, t17.styleKey = null, t17.labelKey = null, t17.labelStyleKey = null, t17.sourceLabelKey = null, t17.sourceLabelStyleKey = null, t17.targetLabelKey = null, t17.targetLabelStyleKey = null, t17.nodeKey = null, t17.hasPie = null;
  }, Gi.applyParsedProperty = function(e22, t17) {
    var n13, r10 = this, a10 = t17, i11 = e22._private.style, o13 = r10.types, s11 = r10.properties[a10.name].type, l11 = a10.bypass, u10 = i11[a10.name], c10 = u10 && u10.bypass, d12 = e22._private, h10 = "mapping", p10 = function(e23) {
      return null == e23 ? null : null != e23.pfValue ? e23.pfValue : e23.value;
    }, f11 = function() {
      var t18 = p10(u10), n14 = p10(a10);
      r10.checkTriggers(e22, a10.name, t18, n14);
    };
    if (a10 && "pie" === a10.name.substr(0, 3) && Me("The pie style properties are deprecated.  Create charts using background images instead."), "curve-style" === t17.name && e22.isEdge() && ("bezier" !== t17.value && e22.isLoop() || "haystack" === t17.value && (e22.source().isParent() || e22.target().isParent())) && (a10 = t17 = this.parse(t17.name, "bezier", l11)), a10.delete)
      return i11[a10.name] = void 0, f11(), true;
    if (a10.deleteBypassed)
      return u10 ? !!u10.bypass && (u10.bypassed = void 0, f11(), true) : (f11(), true);
    if (a10.deleteBypass)
      return u10 ? !!u10.bypass && (i11[a10.name] = u10.bypassed, f11(), true) : (f11(), true);
    var g9 = function() {
      Me("Do not assign mappings to elements without corresponding data (i.e. ele `" + e22.id() + "` has no mapping for property `" + a10.name + "` with data field `" + a10.field + "`); try a `[" + a10.field + "]` selector to limit scope to elements with `" + a10.field + "` defined");
    };
    switch (a10.mapped) {
      case o13.mapData:
        for (var v12, y10 = a10.field.split("."), m12 = d12.data, b11 = 0; b11 < y10.length && m12; b11++) {
          m12 = m12[y10[b11]];
        }
        if (null == m12)
          return g9(), false;
        if (!I6(m12))
          return Me("Do not use continuous mappers without specifying numeric data (i.e. `" + a10.field + ": " + m12 + "` for `" + e22.id() + "` is non-numeric)"), false;
        var x11 = a10.fieldMax - a10.fieldMin;
        if ((v12 = 0 === x11 ? 0 : (m12 - a10.fieldMin) / x11) < 0 ? v12 = 0 : v12 > 1 && (v12 = 1), s11.color) {
          var w10 = a10.valueMin[0], E10 = a10.valueMax[0], k10 = a10.valueMin[1], C9 = a10.valueMax[1], S8 = a10.valueMin[2], D7 = a10.valueMax[2], P10 = null == a10.valueMin[3] ? 1 : a10.valueMin[3], T9 = null == a10.valueMax[3] ? 1 : a10.valueMax[3], M9 = [Math.round(w10 + (E10 - w10) * v12), Math.round(k10 + (C9 - k10) * v12), Math.round(S8 + (D7 - S8) * v12), Math.round(P10 + (T9 - P10) * v12)];
          n13 = { bypass: a10.bypass, name: a10.name, value: M9, strValue: "rgb(" + M9[0] + ", " + M9[1] + ", " + M9[2] + ")" };
        } else {
          if (!s11.number)
            return false;
          var B8 = a10.valueMin + (a10.valueMax - a10.valueMin) * v12;
          n13 = this.parse(a10.name, B8, a10.bypass, h10);
        }
        if (!n13)
          return g9(), false;
        n13.mapping = a10, a10 = n13;
        break;
      case o13.data:
        for (var _7 = a10.field.split("."), N8 = d12.data, z8 = 0; z8 < _7.length && N8; z8++) {
          N8 = N8[_7[z8]];
        }
        if (null != N8 && (n13 = this.parse(a10.name, N8, a10.bypass, h10)), !n13)
          return g9(), false;
        n13.mapping = a10, a10 = n13;
        break;
      case o13.fn:
        var L10 = a10.value, A10 = null != a10.fnValue ? a10.fnValue : L10(e22);
        if (a10.prevFnValue = A10, null == A10)
          return Me("Custom function mappers may not return null (i.e. `" + a10.name + "` for ele `" + e22.id() + "` is null)"), false;
        if (!(n13 = this.parse(a10.name, A10, a10.bypass, h10)))
          return Me("Custom function mappers may not return invalid values for the property type (i.e. `" + a10.name + "` for ele `" + e22.id() + "` is invalid)"), false;
        n13.mapping = Be(a10), a10 = n13;
        break;
      case void 0:
        break;
      default:
        return false;
    }
    return l11 ? (a10.bypassed = c10 ? u10.bypassed : u10, i11[a10.name] = a10) : c10 ? u10.bypassed = a10 : i11[a10.name] = a10, f11(), true;
  }, Gi.cleanElements = function(e22, t17) {
    for (var n13 = 0; n13 < e22.length; n13++) {
      var r10 = e22[n13];
      if (this.clearStyleHints(r10), r10.dirtyCompoundBoundsCache(), r10.dirtyBoundingBoxCache(), t17)
        for (var a10 = r10._private.style, i11 = Object.keys(a10), o13 = 0; o13 < i11.length; o13++) {
          var s11 = i11[o13], l11 = a10[s11];
          null != l11 && (l11.bypass ? l11.bypassed = null : a10[s11] = null);
        }
      else
        r10._private.style = {};
    }
  }, Gi.update = function() {
    this._private.cy.mutableElements().updateStyle();
  }, Gi.updateTransitions = function(e22, t17) {
    var n13 = this, r10 = e22._private, a10 = e22.pstyle("transition-property").value, i11 = e22.pstyle("transition-duration").pfValue, o13 = e22.pstyle("transition-delay").pfValue;
    if (a10.length > 0 && i11 > 0) {
      for (var s11 = {}, l11 = false, u10 = 0; u10 < a10.length; u10++) {
        var c10 = a10[u10], d12 = e22.pstyle(c10), h10 = t17[c10];
        if (h10) {
          var p10 = h10.prev, f11 = null != h10.next ? h10.next : d12, g9 = false, v12 = void 0, y10 = 1e-6;
          p10 && (I6(p10.pfValue) && I6(f11.pfValue) ? (g9 = f11.pfValue - p10.pfValue, v12 = p10.pfValue + y10 * g9) : I6(p10.value) && I6(f11.value) ? (g9 = f11.value - p10.value, v12 = p10.value + y10 * g9) : _5(p10.value) && _5(f11.value) && (g9 = p10.value[0] !== f11.value[0] || p10.value[1] !== f11.value[1] || p10.value[2] !== f11.value[2], v12 = p10.strValue), g9 && (s11[c10] = f11.strValue, this.applyBypass(e22, c10, v12), l11 = true));
        }
      }
      if (!l11)
        return;
      r10.transitioning = true, new rr4(function(t18) {
        o13 > 0 ? e22.delayAnimation(o13).play().promise().then(t18) : t18();
      }).then(function() {
        return e22.animation({ style: s11, duration: i11, easing: e22.pstyle("transition-timing-function").value, queue: false }).play().promise();
      }).then(function() {
        n13.removeBypasses(e22, a10), e22.emitAndNotify("style"), r10.transitioning = false;
      });
    } else
      r10.transitioning && (this.removeBypasses(e22, a10), e22.emitAndNotify("style"), r10.transitioning = false);
  }, Gi.checkTrigger = function(e22, t17, n13, r10, a10, i11) {
    var o13 = this.properties[t17], s11 = a10(o13);
    null != s11 && s11(n13, r10) && i11(o13);
  }, Gi.checkZOrderTrigger = function(e22, t17, n13, r10) {
    var a10 = this;
    this.checkTrigger(e22, t17, n13, r10, function(e23) {
      return e23.triggersZOrder;
    }, function() {
      a10._private.cy.notify("zorder", e22);
    });
  }, Gi.checkBoundsTrigger = function(e22, t17, n13, r10) {
    this.checkTrigger(e22, t17, n13, r10, function(e23) {
      return e23.triggersBounds;
    }, function(a10) {
      e22.dirtyCompoundBoundsCache(), e22.dirtyBoundingBoxCache(), !a10.triggersBoundsOfParallelBeziers || ("curve-style" !== t17 || "bezier" !== n13 && "bezier" !== r10) && ("display" !== t17 || "none" !== n13 && "none" !== r10) || e22.parallelEdges().forEach(function(e23) {
        e23.isBundledBezier() && e23.dirtyBoundingBoxCache();
      });
    });
  }, Gi.checkTriggers = function(e22, t17, n13, r10) {
    e22.dirtyStyleCache(), this.checkZOrderTrigger(e22, t17, n13, r10), this.checkBoundsTrigger(e22, t17, n13, r10);
  };
  var Zi = { applyBypass: function(e22, t17, n13, r10) {
    var a10 = [];
    if ("*" === t17 || "**" === t17) {
      if (void 0 !== n13)
        for (var i11 = 0; i11 < this.properties.length; i11++) {
          var o13 = this.properties[i11].name, s11 = this.parse(o13, n13, true);
          s11 && a10.push(s11);
        }
    } else if (M6(t17)) {
      var l11 = this.parse(t17, n13, true);
      l11 && a10.push(l11);
    } else {
      if (!N6(t17))
        return false;
      var u10 = t17;
      r10 = n13;
      for (var c10 = Object.keys(u10), d12 = 0; d12 < c10.length; d12++) {
        var h10 = c10[d12], p10 = u10[h10];
        if (void 0 === p10 && (p10 = u10[X4(h10)]), void 0 !== p10) {
          var f11 = this.parse(h10, p10, true);
          f11 && a10.push(f11);
        }
      }
    }
    if (0 === a10.length)
      return false;
    for (var g9 = false, v12 = 0; v12 < e22.length; v12++) {
      for (var y10 = e22[v12], m12 = {}, b11 = void 0, x11 = 0; x11 < a10.length; x11++) {
        var w10 = a10[x11];
        if (r10) {
          var E10 = y10.pstyle(w10.name);
          b11 = m12[w10.name] = { prev: E10 };
        }
        g9 = this.applyParsedProperty(y10, Be(w10)) || g9, r10 && (b11.next = y10.pstyle(w10.name));
      }
      g9 && this.updateStyleHints(y10), r10 && this.updateTransitions(y10, m12, true);
    }
    return g9;
  }, overrideBypass: function(e22, t17, n13) {
    t17 = Y4(t17);
    for (var r10 = 0; r10 < e22.length; r10++) {
      var a10 = e22[r10], i11 = a10._private.style[t17], o13 = this.properties[t17].type, s11 = o13.color, l11 = o13.mutiple, u10 = i11 ? null != i11.pfValue ? i11.pfValue : i11.value : null;
      i11 && i11.bypass ? (i11.value = n13, null != i11.pfValue && (i11.pfValue = n13), i11.strValue = s11 ? "rgb(" + n13.join(",") + ")" : l11 ? n13.join(" ") : "" + n13, this.updateStyleHints(a10)) : this.applyBypass(a10, t17, n13), this.checkTriggers(a10, t17, u10, n13);
    }
  }, removeAllBypasses: function(e22, t17) {
    return this.removeBypasses(e22, this.propertyNames, t17);
  }, removeBypasses: function(e22, t17, n13) {
    for (var r10 = 0; r10 < e22.length; r10++) {
      for (var a10 = e22[r10], i11 = {}, o13 = 0; o13 < t17.length; o13++) {
        var s11 = t17[o13], l11 = this.properties[s11], u10 = a10.pstyle(l11.name);
        if (u10 && u10.bypass) {
          var c10 = this.parse(s11, "", true), d12 = i11[l11.name] = { prev: u10 };
          this.applyParsedProperty(a10, c10), d12.next = a10.pstyle(l11.name);
        }
      }
      this.updateStyleHints(a10), n13 && this.updateTransitions(a10, i11, true);
    }
  } };
  var $i = { getEmSizeInPixels: function() {
    var e22 = this.containerCss("font-size");
    return null != e22 ? parseFloat(e22) : 1;
  }, containerCss: function(e22) {
    var t17 = this._private.cy, n13 = t17.container(), r10 = t17.window();
    if (r10 && n13 && r10.getComputedStyle)
      return r10.getComputedStyle(n13).getPropertyValue(e22);
  } };
  var Qi = { getRenderedStyle: function(e22, t17) {
    return t17 ? this.getStylePropertyValue(e22, t17, true) : this.getRawStyle(e22, true);
  }, getRawStyle: function(e22, t17) {
    var n13 = this;
    if (e22 = e22[0]) {
      for (var r10 = {}, a10 = 0; a10 < n13.properties.length; a10++) {
        var i11 = n13.properties[a10], o13 = n13.getStylePropertyValue(e22, i11.name, t17);
        null != o13 && (r10[i11.name] = o13, r10[X4(i11.name)] = o13);
      }
      return r10;
    }
  }, getIndexedStyle: function(e22, t17, n13, r10) {
    var a10 = e22.pstyle(t17)[n13][r10];
    return null != a10 ? a10 : e22.cy().style().getDefaultProperty(t17)[n13][0];
  }, getStylePropertyValue: function(e22, t17, n13) {
    if (e22 = e22[0]) {
      var r10 = this.properties[t17];
      r10.alias && (r10 = r10.pointsTo);
      var a10 = r10.type, i11 = e22.pstyle(r10.name);
      if (i11) {
        var o13 = i11.value, s11 = i11.units, l11 = i11.strValue;
        if (n13 && a10.number && null != o13 && I6(o13)) {
          var u10 = e22.cy().zoom(), c10 = function(e23) {
            return e23 * u10;
          }, d12 = function(e23, t18) {
            return c10(e23) + t18;
          }, h10 = _5(o13);
          return (h10 ? s11.every(function(e23) {
            return null != e23;
          }) : null != s11) ? h10 ? o13.map(function(e23, t18) {
            return d12(e23, s11[t18]);
          }).join(" ") : d12(o13, s11) : h10 ? o13.map(function(e23) {
            return M6(e23) ? e23 : "" + c10(e23);
          }).join(" ") : "" + c10(o13);
        }
        if (null != l11)
          return l11;
      }
      return null;
    }
  }, getAnimationStartStyle: function(e22, t17) {
    for (var n13 = {}, r10 = 0; r10 < t17.length; r10++) {
      var a10 = t17[r10].name, i11 = e22.pstyle(a10);
      void 0 !== i11 && (i11 = N6(i11) ? this.parse(a10, i11.strValue) : this.parse(a10, i11)), i11 && (n13[a10] = i11);
    }
    return n13;
  }, getPropsList: function(e22) {
    var t17 = [], n13 = e22, r10 = this.properties;
    if (n13)
      for (var a10 = Object.keys(n13), i11 = 0; i11 < a10.length; i11++) {
        var o13 = a10[i11], s11 = n13[o13], l11 = r10[o13] || r10[Y4(o13)], u10 = this.parse(l11.name, s11);
        u10 && t17.push(u10);
      }
    return t17;
  }, getNonDefaultPropertiesHash: function(e22, t17, n13) {
    var r10, a10, i11, o13, s11, l11, u10 = n13.slice();
    for (s11 = 0; s11 < t17.length; s11++)
      if (r10 = t17[s11], null != (a10 = e22.pstyle(r10, false)))
        if (null != a10.pfValue)
          u10[0] = he(o13, u10[0]), u10[1] = pe(o13, u10[1]);
        else
          for (i11 = a10.strValue, l11 = 0; l11 < i11.length; l11++)
            o13 = i11.charCodeAt(l11), u10[0] = he(o13, u10[0]), u10[1] = pe(o13, u10[1]);
    return u10;
  } };
  Qi.getPropertiesHash = Qi.getNonDefaultPropertiesHash;
  var Ji = { appendFromJson: function(e22) {
    for (var t17 = this, n13 = 0; n13 < e22.length; n13++) {
      var r10 = e22[n13], a10 = r10.selector, i11 = r10.style || r10.css, o13 = Object.keys(i11);
      t17.selector(a10);
      for (var s11 = 0; s11 < o13.length; s11++) {
        var l11 = o13[s11], u10 = i11[l11];
        t17.css(l11, u10);
      }
    }
    return t17;
  }, fromJson: function(e22) {
    var t17 = this;
    return t17.resetToDefault(), t17.appendFromJson(e22), t17;
  }, json: function() {
    for (var e22 = [], t17 = this.defaultLength; t17 < this.length; t17++) {
      for (var n13 = this[t17], r10 = n13.selector, a10 = n13.properties, i11 = {}, o13 = 0; o13 < a10.length; o13++) {
        var s11 = a10[o13];
        i11[s11.name] = s11.strValue;
      }
      e22.push({ selector: r10 ? r10.toString() : "core", style: i11 });
    }
    return e22;
  } };
  var eo = { appendFromString: function(e22) {
    var t17, n13, r10, a10 = this, i11 = "" + e22;
    function o13() {
      i11 = i11.length > t17.length ? i11.substr(t17.length) : "";
    }
    function s11() {
      n13 = n13.length > r10.length ? n13.substr(r10.length) : "";
    }
    for (i11 = i11.replace(/[/][*](\s|.)+?[*][/]/g, ""); ; ) {
      if (i11.match(/^\s*$/))
        break;
      var l11 = i11.match(/^\s*((?:.|\s)+?)\s*\{((?:.|\s)+?)\}/);
      if (!l11) {
        Me("Halting stylesheet parsing: String stylesheet contains more to parse but no selector and block found in: " + i11);
        break;
      }
      t17 = l11[0];
      var u10 = l11[1];
      if ("core" !== u10) {
        if (new Kr(u10).invalid) {
          Me("Skipping parsing of block: Invalid selector found in string stylesheet: " + u10), o13();
          continue;
        }
      }
      var c10 = l11[2], d12 = false;
      n13 = c10;
      for (var h10 = []; ; ) {
        if (n13.match(/^\s*$/))
          break;
        var p10 = n13.match(/^\s*(.+?)\s*:\s*(.+?)(?:\s*;|\s*$)/);
        if (!p10) {
          Me("Skipping parsing of block: Invalid formatting of style property and value definitions found in:" + c10), d12 = true;
          break;
        }
        r10 = p10[0];
        var f11 = p10[1], g9 = p10[2];
        if (this.properties[f11])
          a10.parse(f11, g9) ? (h10.push({ name: f11, val: g9 }), s11()) : (Me("Skipping property: Invalid property definition in: " + r10), s11());
        else
          Me("Skipping property: Invalid property name in: " + r10), s11();
      }
      if (d12) {
        o13();
        break;
      }
      a10.selector(u10);
      for (var v12 = 0; v12 < h10.length; v12++) {
        var y10 = h10[v12];
        a10.css(y10.name, y10.val);
      }
      o13();
    }
    return a10;
  }, fromString: function(e22) {
    var t17 = this;
    return t17.resetToDefault(), t17.appendFromString(e22), t17;
  } };
  var to = {};
  !function() {
    var e22 = K4, t17 = U5, n13 = $6, r10 = function(e23) {
      return "^" + e23 + "\\s*\\(\\s*([\\w\\.]+)\\s*\\)$";
    }, a10 = function(r11) {
      var a11 = e22 + "|\\w+|" + t17 + "|" + n13 + "|\\#[0-9a-fA-F]{3}|\\#[0-9a-fA-F]{6}";
      return "^" + r11 + "\\s*\\(([\\w\\.]+)\\s*\\,\\s*(" + e22 + ")\\s*\\,\\s*(" + e22 + ")\\s*,\\s*(" + a11 + ")\\s*\\,\\s*(" + a11 + ")\\)$";
    }, i11 = [`^url\\s*\\(\\s*['"]?(.+?)['"]?\\s*\\)$`, "^(none)$", "^(.+)$"];
    to.types = { time: { number: true, min: 0, units: "s|ms", implicitUnits: "ms" }, percent: { number: true, min: 0, max: 100, units: "%", implicitUnits: "%" }, percentages: { number: true, min: 0, max: 100, units: "%", implicitUnits: "%", multiple: true }, zeroOneNumber: { number: true, min: 0, max: 1, unitless: true }, zeroOneNumbers: { number: true, min: 0, max: 1, unitless: true, multiple: true }, nOneOneNumber: { number: true, min: -1, max: 1, unitless: true }, nonNegativeInt: { number: true, min: 0, integer: true, unitless: true }, position: { enums: ["parent", "origin"] }, nodeSize: { number: true, min: 0, enums: ["label"] }, number: { number: true, unitless: true }, numbers: { number: true, unitless: true, multiple: true }, positiveNumber: { number: true, unitless: true, min: 0, strictMin: true }, size: { number: true, min: 0 }, bidirectionalSize: { number: true }, bidirectionalSizeMaybePercent: { number: true, allowPercent: true }, bidirectionalSizes: { number: true, multiple: true }, sizeMaybePercent: { number: true, min: 0, allowPercent: true }, axisDirection: { enums: ["horizontal", "leftward", "rightward", "vertical", "upward", "downward", "auto"] }, paddingRelativeTo: { enums: ["width", "height", "average", "min", "max"] }, bgWH: { number: true, min: 0, allowPercent: true, enums: ["auto"], multiple: true }, bgPos: { number: true, allowPercent: true, multiple: true }, bgRelativeTo: { enums: ["inner", "include-padding"], multiple: true }, bgRepeat: { enums: ["repeat", "repeat-x", "repeat-y", "no-repeat"], multiple: true }, bgFit: { enums: ["none", "contain", "cover"], multiple: true }, bgCrossOrigin: { enums: ["anonymous", "use-credentials", "null"], multiple: true }, bgClip: { enums: ["none", "node"], multiple: true }, bgContainment: { enums: ["inside", "over"], multiple: true }, color: { color: true }, colors: { color: true, multiple: true }, fill: { enums: ["solid", "linear-gradient", "radial-gradient"] }, bool: { enums: ["yes", "no"] }, bools: { enums: ["yes", "no"], multiple: true }, lineStyle: { enums: ["solid", "dotted", "dashed"] }, lineCap: { enums: ["butt", "round", "square"] }, borderStyle: { enums: ["solid", "dotted", "dashed", "double"] }, curveStyle: { enums: ["bezier", "unbundled-bezier", "haystack", "segments", "straight", "straight-triangle", "taxi"] }, fontFamily: { regex: '^([\\w- \\"]+(?:\\s*,\\s*[\\w- \\"]+)*)$' }, fontStyle: { enums: ["italic", "normal", "oblique"] }, fontWeight: { enums: ["normal", "bold", "bolder", "lighter", "100", "200", "300", "400", "500", "600", "800", "900", 100, 200, 300, 400, 500, 600, 700, 800, 900] }, textDecoration: { enums: ["none", "underline", "overline", "line-through"] }, textTransform: { enums: ["none", "uppercase", "lowercase"] }, textWrap: { enums: ["none", "wrap", "ellipsis"] }, textOverflowWrap: { enums: ["whitespace", "anywhere"] }, textBackgroundShape: { enums: ["rectangle", "roundrectangle", "round-rectangle"] }, nodeShape: { enums: ["rectangle", "roundrectangle", "round-rectangle", "cutrectangle", "cut-rectangle", "bottomroundrectangle", "bottom-round-rectangle", "barrel", "ellipse", "triangle", "round-triangle", "square", "pentagon", "round-pentagon", "hexagon", "round-hexagon", "concavehexagon", "concave-hexagon", "heptagon", "round-heptagon", "octagon", "round-octagon", "tag", "round-tag", "star", "diamond", "round-diamond", "vee", "rhomboid", "right-rhomboid", "polygon"] }, overlayShape: { enums: ["roundrectangle", "round-rectangle", "ellipse"] }, compoundIncludeLabels: { enums: ["include", "exclude"] }, arrowShape: { enums: ["tee", "triangle", "triangle-tee", "circle-triangle", "triangle-cross", "triangle-backcurve", "vee", "square", "circle", "diamond", "chevron", "none"] }, arrowFill: { enums: ["filled", "hollow"] }, display: { enums: ["element", "none"] }, visibility: { enums: ["hidden", "visible"] }, zCompoundDepth: { enums: ["bottom", "orphan", "auto", "top"] }, zIndexCompare: { enums: ["auto", "manual"] }, valign: { enums: ["top", "center", "bottom"] }, halign: { enums: ["left", "center", "right"] }, justification: { enums: ["left", "center", "right", "auto"] }, text: { string: true }, data: { mapping: true, regex: r10("data") }, layoutData: { mapping: true, regex: r10("layoutData") }, scratch: { mapping: true, regex: r10("scratch") }, mapData: { mapping: true, regex: a10("mapData") }, mapLayoutData: { mapping: true, regex: a10("mapLayoutData") }, mapScratch: { mapping: true, regex: a10("mapScratch") }, fn: { mapping: true, fn: true }, url: { regexes: i11, singleRegexMatchValue: true }, urls: { regexes: i11, singleRegexMatchValue: true, multiple: true }, propList: { propList: true }, angle: { number: true, units: "deg|rad", implicitUnits: "rad" }, textRotation: { number: true, units: "deg|rad", implicitUnits: "rad", enums: ["none", "autorotate"] }, polygonPointList: { number: true, multiple: true, evenMultiple: true, min: -1, max: 1, unitless: true }, edgeDistances: { enums: ["intersection", "node-position"] }, edgeEndpoint: { number: true, multiple: true, units: "%|px|em|deg|rad", implicitUnits: "px", enums: ["inside-to-node", "outside-to-node", "outside-to-node-or-label", "outside-to-line", "outside-to-line-or-label"], singleEnum: true, validate: function(e23, t18) {
      switch (e23.length) {
        case 2:
          return "deg" !== t18[0] && "rad" !== t18[0] && "deg" !== t18[1] && "rad" !== t18[1];
        case 1:
          return M6(e23[0]) || "deg" === t18[0] || "rad" === t18[0];
        default:
          return false;
      }
    } }, easing: { regexes: ["^(spring)\\s*\\(\\s*(" + e22 + ")\\s*,\\s*(" + e22 + ")\\s*\\)$", "^(cubic-bezier)\\s*\\(\\s*(" + e22 + ")\\s*,\\s*(" + e22 + ")\\s*,\\s*(" + e22 + ")\\s*,\\s*(" + e22 + ")\\s*\\)$"], enums: ["linear", "ease", "ease-in", "ease-out", "ease-in-out", "ease-in-sine", "ease-out-sine", "ease-in-out-sine", "ease-in-quad", "ease-out-quad", "ease-in-out-quad", "ease-in-cubic", "ease-out-cubic", "ease-in-out-cubic", "ease-in-quart", "ease-out-quart", "ease-in-out-quart", "ease-in-quint", "ease-out-quint", "ease-in-out-quint", "ease-in-expo", "ease-out-expo", "ease-in-out-expo", "ease-in-circ", "ease-out-circ", "ease-in-out-circ"] }, gradientDirection: { enums: ["to-bottom", "to-top", "to-left", "to-right", "to-bottom-right", "to-bottom-left", "to-top-right", "to-top-left", "to-right-bottom", "to-left-bottom", "to-right-top", "to-left-top"] }, boundsExpansion: { number: true, multiple: true, min: 0, validate: function(e23) {
      var t18 = e23.length;
      return 1 === t18 || 2 === t18 || 4 === t18;
    } } };
    var o13 = { zeroNonZero: function(e23, t18) {
      return (null == e23 || null == t18) && e23 !== t18 || (0 == e23 && 0 != t18 || 0 != e23 && 0 == t18);
    }, any: function(e23, t18) {
      return e23 != t18;
    }, emptyNonEmpty: function(e23, t18) {
      var n14 = F6(e23), r11 = F6(t18);
      return n14 && !r11 || !n14 && r11;
    } }, s11 = to.types, l11 = [{ name: "label", type: s11.text, triggersBounds: o13.any, triggersZOrder: o13.emptyNonEmpty }, { name: "text-rotation", type: s11.textRotation, triggersBounds: o13.any }, { name: "text-margin-x", type: s11.bidirectionalSize, triggersBounds: o13.any }, { name: "text-margin-y", type: s11.bidirectionalSize, triggersBounds: o13.any }], u10 = [{ name: "source-label", type: s11.text, triggersBounds: o13.any }, { name: "source-text-rotation", type: s11.textRotation, triggersBounds: o13.any }, { name: "source-text-margin-x", type: s11.bidirectionalSize, triggersBounds: o13.any }, { name: "source-text-margin-y", type: s11.bidirectionalSize, triggersBounds: o13.any }, { name: "source-text-offset", type: s11.size, triggersBounds: o13.any }], c10 = [{ name: "target-label", type: s11.text, triggersBounds: o13.any }, { name: "target-text-rotation", type: s11.textRotation, triggersBounds: o13.any }, { name: "target-text-margin-x", type: s11.bidirectionalSize, triggersBounds: o13.any }, { name: "target-text-margin-y", type: s11.bidirectionalSize, triggersBounds: o13.any }, { name: "target-text-offset", type: s11.size, triggersBounds: o13.any }], d12 = [{ name: "font-family", type: s11.fontFamily, triggersBounds: o13.any }, { name: "font-style", type: s11.fontStyle, triggersBounds: o13.any }, { name: "font-weight", type: s11.fontWeight, triggersBounds: o13.any }, { name: "font-size", type: s11.size, triggersBounds: o13.any }, { name: "text-transform", type: s11.textTransform, triggersBounds: o13.any }, { name: "text-wrap", type: s11.textWrap, triggersBounds: o13.any }, { name: "text-overflow-wrap", type: s11.textOverflowWrap, triggersBounds: o13.any }, { name: "text-max-width", type: s11.size, triggersBounds: o13.any }, { name: "text-outline-width", type: s11.size, triggersBounds: o13.any }, { name: "line-height", type: s11.positiveNumber, triggersBounds: o13.any }], h10 = [{ name: "text-valign", type: s11.valign, triggersBounds: o13.any }, { name: "text-halign", type: s11.halign, triggersBounds: o13.any }, { name: "color", type: s11.color }, { name: "text-outline-color", type: s11.color }, { name: "text-outline-opacity", type: s11.zeroOneNumber }, { name: "text-background-color", type: s11.color }, { name: "text-background-opacity", type: s11.zeroOneNumber }, { name: "text-background-padding", type: s11.size, triggersBounds: o13.any }, { name: "text-border-opacity", type: s11.zeroOneNumber }, { name: "text-border-color", type: s11.color }, { name: "text-border-width", type: s11.size, triggersBounds: o13.any }, { name: "text-border-style", type: s11.borderStyle, triggersBounds: o13.any }, { name: "text-background-shape", type: s11.textBackgroundShape, triggersBounds: o13.any }, { name: "text-justification", type: s11.justification }], p10 = [{ name: "events", type: s11.bool }, { name: "text-events", type: s11.bool }], f11 = [{ name: "display", type: s11.display, triggersZOrder: o13.any, triggersBounds: o13.any, triggersBoundsOfParallelBeziers: true }, { name: "visibility", type: s11.visibility, triggersZOrder: o13.any }, { name: "opacity", type: s11.zeroOneNumber, triggersZOrder: o13.zeroNonZero }, { name: "text-opacity", type: s11.zeroOneNumber }, { name: "min-zoomed-font-size", type: s11.size }, { name: "z-compound-depth", type: s11.zCompoundDepth, triggersZOrder: o13.any }, { name: "z-index-compare", type: s11.zIndexCompare, triggersZOrder: o13.any }, { name: "z-index", type: s11.nonNegativeInt, triggersZOrder: o13.any }], g9 = [{ name: "overlay-padding", type: s11.size, triggersBounds: o13.any }, { name: "overlay-color", type: s11.color }, { name: "overlay-opacity", type: s11.zeroOneNumber, triggersBounds: o13.zeroNonZero }, { name: "overlay-shape", type: s11.overlayShape, triggersBounds: o13.any }], v12 = [{ name: "underlay-padding", type: s11.size, triggersBounds: o13.any }, { name: "underlay-color", type: s11.color }, { name: "underlay-opacity", type: s11.zeroOneNumber, triggersBounds: o13.zeroNonZero }, { name: "underlay-shape", type: s11.overlayShape, triggersBounds: o13.any }], y10 = [{ name: "transition-property", type: s11.propList }, { name: "transition-duration", type: s11.time }, { name: "transition-delay", type: s11.time }, { name: "transition-timing-function", type: s11.easing }], m12 = function(e23, t18) {
      return "label" === t18.value ? -e23.poolIndex() : t18.pfValue;
    }, b11 = [{ name: "height", type: s11.nodeSize, triggersBounds: o13.any, hashOverride: m12 }, { name: "width", type: s11.nodeSize, triggersBounds: o13.any, hashOverride: m12 }, { name: "shape", type: s11.nodeShape, triggersBounds: o13.any }, { name: "shape-polygon-points", type: s11.polygonPointList, triggersBounds: o13.any }, { name: "background-color", type: s11.color }, { name: "background-fill", type: s11.fill }, { name: "background-opacity", type: s11.zeroOneNumber }, { name: "background-blacken", type: s11.nOneOneNumber }, { name: "background-gradient-stop-colors", type: s11.colors }, { name: "background-gradient-stop-positions", type: s11.percentages }, { name: "background-gradient-direction", type: s11.gradientDirection }, { name: "padding", type: s11.sizeMaybePercent, triggersBounds: o13.any }, { name: "padding-relative-to", type: s11.paddingRelativeTo, triggersBounds: o13.any }, { name: "bounds-expansion", type: s11.boundsExpansion, triggersBounds: o13.any }], x11 = [{ name: "border-color", type: s11.color }, { name: "border-opacity", type: s11.zeroOneNumber }, { name: "border-width", type: s11.size, triggersBounds: o13.any }, { name: "border-style", type: s11.borderStyle }], w10 = [{ name: "background-image", type: s11.urls }, { name: "background-image-crossorigin", type: s11.bgCrossOrigin }, { name: "background-image-opacity", type: s11.zeroOneNumbers }, { name: "background-image-containment", type: s11.bgContainment }, { name: "background-image-smoothing", type: s11.bools }, { name: "background-position-x", type: s11.bgPos }, { name: "background-position-y", type: s11.bgPos }, { name: "background-width-relative-to", type: s11.bgRelativeTo }, { name: "background-height-relative-to", type: s11.bgRelativeTo }, { name: "background-repeat", type: s11.bgRepeat }, { name: "background-fit", type: s11.bgFit }, { name: "background-clip", type: s11.bgClip }, { name: "background-width", type: s11.bgWH }, { name: "background-height", type: s11.bgWH }, { name: "background-offset-x", type: s11.bgPos }, { name: "background-offset-y", type: s11.bgPos }], E10 = [{ name: "position", type: s11.position, triggersBounds: o13.any }, { name: "compound-sizing-wrt-labels", type: s11.compoundIncludeLabels, triggersBounds: o13.any }, { name: "min-width", type: s11.size, triggersBounds: o13.any }, { name: "min-width-bias-left", type: s11.sizeMaybePercent, triggersBounds: o13.any }, { name: "min-width-bias-right", type: s11.sizeMaybePercent, triggersBounds: o13.any }, { name: "min-height", type: s11.size, triggersBounds: o13.any }, { name: "min-height-bias-top", type: s11.sizeMaybePercent, triggersBounds: o13.any }, { name: "min-height-bias-bottom", type: s11.sizeMaybePercent, triggersBounds: o13.any }], k10 = [{ name: "line-style", type: s11.lineStyle }, { name: "line-color", type: s11.color }, { name: "line-fill", type: s11.fill }, { name: "line-cap", type: s11.lineCap }, { name: "line-opacity", type: s11.zeroOneNumber }, { name: "line-dash-pattern", type: s11.numbers }, { name: "line-dash-offset", type: s11.number }, { name: "line-gradient-stop-colors", type: s11.colors }, { name: "line-gradient-stop-positions", type: s11.percentages }, { name: "curve-style", type: s11.curveStyle, triggersBounds: o13.any, triggersBoundsOfParallelBeziers: true }, { name: "haystack-radius", type: s11.zeroOneNumber, triggersBounds: o13.any }, { name: "source-endpoint", type: s11.edgeEndpoint, triggersBounds: o13.any }, { name: "target-endpoint", type: s11.edgeEndpoint, triggersBounds: o13.any }, { name: "control-point-step-size", type: s11.size, triggersBounds: o13.any }, { name: "control-point-distances", type: s11.bidirectionalSizes, triggersBounds: o13.any }, { name: "control-point-weights", type: s11.numbers, triggersBounds: o13.any }, { name: "segment-distances", type: s11.bidirectionalSizes, triggersBounds: o13.any }, { name: "segment-weights", type: s11.numbers, triggersBounds: o13.any }, { name: "taxi-turn", type: s11.bidirectionalSizeMaybePercent, triggersBounds: o13.any }, { name: "taxi-turn-min-distance", type: s11.size, triggersBounds: o13.any }, { name: "taxi-direction", type: s11.axisDirection, triggersBounds: o13.any }, { name: "edge-distances", type: s11.edgeDistances, triggersBounds: o13.any }, { name: "arrow-scale", type: s11.positiveNumber, triggersBounds: o13.any }, { name: "loop-direction", type: s11.angle, triggersBounds: o13.any }, { name: "loop-sweep", type: s11.angle, triggersBounds: o13.any }, { name: "source-distance-from-node", type: s11.size, triggersBounds: o13.any }, { name: "target-distance-from-node", type: s11.size, triggersBounds: o13.any }], C9 = [{ name: "ghost", type: s11.bool, triggersBounds: o13.any }, { name: "ghost-offset-x", type: s11.bidirectionalSize, triggersBounds: o13.any }, { name: "ghost-offset-y", type: s11.bidirectionalSize, triggersBounds: o13.any }, { name: "ghost-opacity", type: s11.zeroOneNumber }], S8 = [{ name: "selection-box-color", type: s11.color }, { name: "selection-box-opacity", type: s11.zeroOneNumber }, { name: "selection-box-border-color", type: s11.color }, { name: "selection-box-border-width", type: s11.size }, { name: "active-bg-color", type: s11.color }, { name: "active-bg-opacity", type: s11.zeroOneNumber }, { name: "active-bg-size", type: s11.size }, { name: "outside-texture-bg-color", type: s11.color }, { name: "outside-texture-bg-opacity", type: s11.zeroOneNumber }], D7 = [];
    to.pieBackgroundN = 16, D7.push({ name: "pie-size", type: s11.sizeMaybePercent });
    for (var P10 = 1; P10 <= to.pieBackgroundN; P10++)
      D7.push({ name: "pie-" + P10 + "-background-color", type: s11.color }), D7.push({ name: "pie-" + P10 + "-background-size", type: s11.percent }), D7.push({ name: "pie-" + P10 + "-background-opacity", type: s11.zeroOneNumber });
    var T9 = [], B8 = to.arrowPrefixes = ["source", "mid-source", "target", "mid-target"];
    [{ name: "arrow-shape", type: s11.arrowShape, triggersBounds: o13.any }, { name: "arrow-color", type: s11.color }, { name: "arrow-fill", type: s11.arrowFill }].forEach(function(e23) {
      B8.forEach(function(t18) {
        var n14 = t18 + "-" + e23.name, r11 = e23.type, a11 = e23.triggersBounds;
        T9.push({ name: n14, type: r11, triggersBounds: a11 });
      });
    }, {});
    var _7 = to.properties = [].concat(p10, y10, f11, g9, v12, C9, h10, d12, l11, u10, c10, b11, x11, w10, D7, E10, k10, T9, S8), N8 = to.propertyGroups = { behavior: p10, transition: y10, visibility: f11, overlay: g9, underlay: v12, ghost: C9, commonLabel: h10, labelDimensions: d12, mainLabel: l11, sourceLabel: u10, targetLabel: c10, nodeBody: b11, nodeBorder: x11, backgroundImage: w10, pie: D7, compound: E10, edgeLine: k10, edgeArrow: T9, core: S8 }, I8 = to.propertyGroupNames = {};
    (to.propertyGroupKeys = Object.keys(N8)).forEach(function(e23) {
      I8[e23] = N8[e23].map(function(e24) {
        return e24.name;
      }), N8[e23].forEach(function(t18) {
        return t18.groupKey = e23;
      });
    });
    var z8 = to.aliases = [{ name: "content", pointsTo: "label" }, { name: "control-point-distance", pointsTo: "control-point-distances" }, { name: "control-point-weight", pointsTo: "control-point-weights" }, { name: "edge-text-rotation", pointsTo: "text-rotation" }, { name: "padding-left", pointsTo: "padding" }, { name: "padding-right", pointsTo: "padding" }, { name: "padding-top", pointsTo: "padding" }, { name: "padding-bottom", pointsTo: "padding" }];
    to.propertyNames = _7.map(function(e23) {
      return e23.name;
    });
    for (var L10 = 0; L10 < _7.length; L10++) {
      var A10 = _7[L10];
      _7[A10.name] = A10;
    }
    for (var O9 = 0; O9 < z8.length; O9++) {
      var R8 = z8[O9], V8 = _7[R8.pointsTo], q8 = { name: R8.name, alias: true, pointsTo: V8 };
      _7.push(q8), _7[R8.name] = q8;
    }
  }(), to.getDefaultProperty = function(e22) {
    return this.getDefaultProperties()[e22];
  }, to.getDefaultProperties = function() {
    var e22 = this._private;
    if (null != e22.defaultProperties)
      return e22.defaultProperties;
    for (var t17 = J4({ "selection-box-color": "#ddd", "selection-box-opacity": 0.65, "selection-box-border-color": "#aaa", "selection-box-border-width": 1, "active-bg-color": "black", "active-bg-opacity": 0.15, "active-bg-size": 30, "outside-texture-bg-color": "#000", "outside-texture-bg-opacity": 0.125, events: "yes", "text-events": "no", "text-valign": "top", "text-halign": "center", "text-justification": "auto", "line-height": 1, color: "#000", "text-outline-color": "#000", "text-outline-width": 0, "text-outline-opacity": 1, "text-opacity": 1, "text-decoration": "none", "text-transform": "none", "text-wrap": "none", "text-overflow-wrap": "whitespace", "text-max-width": 9999, "text-background-color": "#000", "text-background-opacity": 0, "text-background-shape": "rectangle", "text-background-padding": 0, "text-border-opacity": 0, "text-border-width": 0, "text-border-style": "solid", "text-border-color": "#000", "font-family": "Helvetica Neue, Helvetica, sans-serif", "font-style": "normal", "font-weight": "normal", "font-size": 16, "min-zoomed-font-size": 0, "text-rotation": "none", "source-text-rotation": "none", "target-text-rotation": "none", visibility: "visible", display: "element", opacity: 1, "z-compound-depth": "auto", "z-index-compare": "auto", "z-index": 0, label: "", "text-margin-x": 0, "text-margin-y": 0, "source-label": "", "source-text-offset": 0, "source-text-margin-x": 0, "source-text-margin-y": 0, "target-label": "", "target-text-offset": 0, "target-text-margin-x": 0, "target-text-margin-y": 0, "overlay-opacity": 0, "overlay-color": "#000", "overlay-padding": 10, "overlay-shape": "round-rectangle", "underlay-opacity": 0, "underlay-color": "#000", "underlay-padding": 10, "underlay-shape": "round-rectangle", "transition-property": "none", "transition-duration": 0, "transition-delay": 0, "transition-timing-function": "linear", "background-blacken": 0, "background-color": "#999", "background-fill": "solid", "background-opacity": 1, "background-image": "none", "background-image-crossorigin": "anonymous", "background-image-opacity": 1, "background-image-containment": "inside", "background-image-smoothing": "yes", "background-position-x": "50%", "background-position-y": "50%", "background-offset-x": 0, "background-offset-y": 0, "background-width-relative-to": "include-padding", "background-height-relative-to": "include-padding", "background-repeat": "no-repeat", "background-fit": "none", "background-clip": "node", "background-width": "auto", "background-height": "auto", "border-color": "#000", "border-opacity": 1, "border-width": 0, "border-style": "solid", height: 30, width: 30, shape: "ellipse", "shape-polygon-points": "-1, -1,   1, -1,   1, 1,   -1, 1", "bounds-expansion": 0, "background-gradient-direction": "to-bottom", "background-gradient-stop-colors": "#999", "background-gradient-stop-positions": "0%", ghost: "no", "ghost-offset-y": 0, "ghost-offset-x": 0, "ghost-opacity": 0, padding: 0, "padding-relative-to": "width", position: "origin", "compound-sizing-wrt-labels": "include", "min-width": 0, "min-width-bias-left": 0, "min-width-bias-right": 0, "min-height": 0, "min-height-bias-top": 0, "min-height-bias-bottom": 0 }, { "pie-size": "100%" }, [{ name: "pie-{{i}}-background-color", value: "black" }, { name: "pie-{{i}}-background-size", value: "0%" }, { name: "pie-{{i}}-background-opacity", value: 1 }].reduce(function(e23, t18) {
      for (var n14 = 1; n14 <= to.pieBackgroundN; n14++) {
        var r11 = t18.name.replace("{{i}}", n14), a11 = t18.value;
        e23[r11] = a11;
      }
      return e23;
    }, {}), { "line-style": "solid", "line-color": "#999", "line-fill": "solid", "line-cap": "butt", "line-opacity": 1, "line-gradient-stop-colors": "#999", "line-gradient-stop-positions": "0%", "control-point-step-size": 40, "control-point-weights": 0.5, "segment-weights": 0.5, "segment-distances": 20, "taxi-turn": "50%", "taxi-turn-min-distance": 10, "taxi-direction": "auto", "edge-distances": "intersection", "curve-style": "haystack", "haystack-radius": 0, "arrow-scale": 1, "loop-direction": "-45deg", "loop-sweep": "-90deg", "source-distance-from-node": 0, "target-distance-from-node": 0, "source-endpoint": "outside-to-node", "target-endpoint": "outside-to-node", "line-dash-pattern": [6, 3], "line-dash-offset": 0 }, [{ name: "arrow-shape", value: "none" }, { name: "arrow-color", value: "#999" }, { name: "arrow-fill", value: "filled" }].reduce(function(e23, t18) {
      return to.arrowPrefixes.forEach(function(n14) {
        var r11 = n14 + "-" + t18.name, a11 = t18.value;
        e23[r11] = a11;
      }), e23;
    }, {})), n13 = {}, r10 = 0; r10 < this.properties.length; r10++) {
      var a10 = this.properties[r10];
      if (!a10.pointsTo) {
        var i11 = a10.name, o13 = t17[i11], s11 = this.parse(i11, o13);
        n13[i11] = s11;
      }
    }
    return e22.defaultProperties = n13, e22.defaultProperties;
  }, to.addDefaultStylesheet = function() {
    this.selector(":parent").css({ shape: "rectangle", padding: 10, "background-color": "#eee", "border-color": "#ccc", "border-width": 1 }).selector("edge").css({ width: 3 }).selector(":loop").css({ "curve-style": "bezier" }).selector("edge:compound").css({ "curve-style": "bezier", "source-endpoint": "outside-to-line", "target-endpoint": "outside-to-line" }).selector(":selected").css({ "background-color": "#0169D9", "line-color": "#0169D9", "source-arrow-color": "#0169D9", "target-arrow-color": "#0169D9", "mid-source-arrow-color": "#0169D9", "mid-target-arrow-color": "#0169D9" }).selector(":parent:selected").css({ "background-color": "#CCE1F9", "border-color": "#aec8e5" }).selector(":active").css({ "overlay-color": "black", "overlay-padding": 10, "overlay-opacity": 0.25 }), this.defaultLength = this.length;
  };
  var no = { parse: function(e22, t17, n13, r10) {
    var a10 = this;
    if (B4(t17))
      return a10.parseImplWarn(e22, t17, n13, r10);
    var i11, o13 = ye(e22, "" + t17, n13 ? "t" : "f", "mapping" === r10 || true === r10 || false === r10 || null == r10 ? "dontcare" : r10), s11 = a10.propCache = a10.propCache || [];
    return (i11 = s11[o13]) || (i11 = s11[o13] = a10.parseImplWarn(e22, t17, n13, r10)), (n13 || "mapping" === r10) && (i11 = Be(i11)) && (i11.value = Be(i11.value)), i11;
  }, parseImplWarn: function(e22, t17, n13, r10) {
    var a10 = this.parseImpl(e22, t17, n13, r10);
    return a10 || null == t17 || Me("The style property `".concat(e22, ": ").concat(t17, "` is invalid")), !a10 || "width" !== a10.name && "height" !== a10.name || "label" !== t17 || Me("The style value of `label` is deprecated for `" + a10.name + "`"), a10;
  } };
  no.parseImpl = function(e22, t17, n13, r10) {
    var a10 = this;
    e22 = Y4(e22);
    var i11 = a10.properties[e22], o13 = t17, s11 = a10.types;
    if (!i11)
      return null;
    if (void 0 === t17)
      return null;
    i11.alias && (i11 = i11.pointsTo, e22 = i11.name);
    var l11 = M6(t17);
    l11 && (t17 = t17.trim());
    var u10, c10, d12 = i11.type;
    if (!d12)
      return null;
    if (n13 && ("" === t17 || null === t17))
      return { name: e22, value: t17, bypass: true, deleteBypass: true };
    if (B4(t17))
      return { name: e22, value: t17, strValue: "fn", mapped: s11.fn, bypass: n13 };
    if (!l11 || r10 || t17.length < 7 || "a" !== t17[1])
      ;
    else {
      if (t17.length >= 7 && "d" === t17[0] && (u10 = new RegExp(s11.data.regex).exec(t17))) {
        if (n13)
          return false;
        var h10 = s11.data;
        return { name: e22, value: u10, strValue: "" + t17, mapped: h10, field: u10[1], bypass: n13 };
      }
      if (t17.length >= 10 && "m" === t17[0] && (c10 = new RegExp(s11.mapData.regex).exec(t17))) {
        if (n13)
          return false;
        if (d12.multiple)
          return false;
        var p10 = s11.mapData;
        if (!d12.color && !d12.number)
          return false;
        var f11 = this.parse(e22, c10[4]);
        if (!f11 || f11.mapped)
          return false;
        var g9 = this.parse(e22, c10[5]);
        if (!g9 || g9.mapped)
          return false;
        if (f11.pfValue === g9.pfValue || f11.strValue === g9.strValue)
          return Me("`" + e22 + ": " + t17 + "` is not a valid mapper because the output range is zero; converting to `" + e22 + ": " + f11.strValue + "`"), this.parse(e22, f11.strValue);
        if (d12.color) {
          var v12 = f11.value, y10 = g9.value;
          if (!(v12[0] !== y10[0] || v12[1] !== y10[1] || v12[2] !== y10[2] || v12[3] !== y10[3] && (null != v12[3] && 1 !== v12[3] || null != y10[3] && 1 !== y10[3])))
            return false;
        }
        return { name: e22, value: c10, strValue: "" + t17, mapped: p10, field: c10[1], fieldMin: parseFloat(c10[2]), fieldMax: parseFloat(c10[3]), valueMin: f11.value, valueMax: g9.value, bypass: n13 };
      }
    }
    if (d12.multiple && "multiple" !== r10) {
      var m12;
      if (m12 = l11 ? t17.split(/\s+/) : _5(t17) ? t17 : [t17], d12.evenMultiple && m12.length % 2 != 0)
        return null;
      for (var b11 = [], x11 = [], w10 = [], E10 = "", k10 = false, C9 = 0; C9 < m12.length; C9++) {
        var S8 = a10.parse(e22, m12[C9], n13, "multiple");
        k10 = k10 || M6(S8.value), b11.push(S8.value), w10.push(null != S8.pfValue ? S8.pfValue : S8.value), x11.push(S8.units), E10 += (C9 > 0 ? " " : "") + S8.strValue;
      }
      return d12.validate && !d12.validate(b11, x11) ? null : d12.singleEnum && k10 ? 1 === b11.length && M6(b11[0]) ? { name: e22, value: b11[0], strValue: b11[0], bypass: n13 } : null : { name: e22, value: b11, pfValue: w10, strValue: E10, bypass: n13, units: x11 };
    }
    var D7, P10, T9 = function() {
      for (var r11 = 0; r11 < d12.enums.length; r11++) {
        if (d12.enums[r11] === t17)
          return { name: e22, value: t17, strValue: "" + t17, bypass: n13 };
      }
      return null;
    };
    if (d12.number) {
      var N8, z8 = "px";
      if (d12.units && (N8 = d12.units), d12.implicitUnits && (z8 = d12.implicitUnits), !d12.unitless)
        if (l11) {
          var L10 = "px|em" + (d12.allowPercent ? "|\\%" : "");
          N8 && (L10 = N8);
          var A10 = t17.match("^(" + K4 + ")(" + L10 + ")?$");
          A10 && (t17 = A10[1], N8 = A10[2] || z8);
        } else
          N8 && !d12.implicitUnits || (N8 = z8);
      if (t17 = parseFloat(t17), isNaN(t17) && void 0 === d12.enums)
        return null;
      if (isNaN(t17) && void 0 !== d12.enums)
        return t17 = o13, T9();
      if (d12.integer && (!I6(P10 = t17) || Math.floor(P10) !== P10))
        return null;
      if (void 0 !== d12.min && (t17 < d12.min || d12.strictMin && t17 === d12.min) || void 0 !== d12.max && (t17 > d12.max || d12.strictMax && t17 === d12.max))
        return null;
      var O9 = { name: e22, value: t17, strValue: "" + t17 + (N8 || ""), units: N8, bypass: n13 };
      return d12.unitless || "px" !== N8 && "em" !== N8 ? O9.pfValue = t17 : O9.pfValue = "px" !== N8 && N8 ? this.getEmSizeInPixels() * t17 : t17, "ms" !== N8 && "s" !== N8 || (O9.pfValue = "ms" === N8 ? t17 : 1e3 * t17), "deg" !== N8 && "rad" !== N8 || (O9.pfValue = "rad" === N8 ? t17 : (D7 = t17, Math.PI * D7 / 180)), "%" === N8 && (O9.pfValue = t17 / 100), O9;
    }
    if (d12.propList) {
      var R8 = [], V8 = "" + t17;
      if ("none" === V8)
        ;
      else {
        for (var F9 = V8.split(/\s*,\s*|\s+/), q8 = 0; q8 < F9.length; q8++) {
          var j9 = F9[q8].trim();
          a10.properties[j9] ? R8.push(j9) : Me("`" + j9 + "` is not a valid property name");
        }
        if (0 === R8.length)
          return null;
      }
      return { name: e22, value: R8, strValue: 0 === R8.length ? "none" : R8.join(" "), bypass: n13 };
    }
    if (d12.color) {
      var X6 = ee(t17);
      return X6 ? { name: e22, value: X6, pfValue: X6, strValue: "rgb(" + X6[0] + "," + X6[1] + "," + X6[2] + ")", bypass: n13 } : null;
    }
    if (d12.regex || d12.regexes) {
      if (d12.enums) {
        var W8 = T9();
        if (W8)
          return W8;
      }
      for (var H8 = d12.regexes ? d12.regexes : [d12.regex], G6 = 0; G6 < H8.length; G6++) {
        var U7 = new RegExp(H8[G6]).exec(t17);
        if (U7)
          return { name: e22, value: d12.singleRegexMatchValue ? U7[1] : U7, strValue: "" + t17, bypass: n13 };
      }
      return null;
    }
    return d12.string ? { name: e22, value: "" + t17, strValue: "" + t17, bypass: n13 } : d12.enums ? T9() : null;
  };
  var ro = function e12(t17) {
    if (!(this instanceof e12))
      return new e12(t17);
    R4(t17) ? (this._private = { cy: t17, coreStyle: {} }, this.length = 0, this.resetToDefault()) : Pe("A style must have a core reference");
  };
  var ao = ro.prototype;
  ao.instanceString = function() {
    return "style";
  }, ao.clear = function() {
    for (var e22 = this._private, t17 = e22.cy.elements(), n13 = 0; n13 < this.length; n13++)
      this[n13] = void 0;
    return this.length = 0, e22.contextStyles = {}, e22.propDiffs = {}, this.cleanElements(t17, true), t17.forEach(function(e23) {
      var t18 = e23[0]._private;
      t18.styleDirty = true, t18.appliedInitStyle = false;
    }), this;
  }, ao.resetToDefault = function() {
    return this.clear(), this.addDefaultStylesheet(), this;
  }, ao.core = function(e22) {
    return this._private.coreStyle[e22] || this.getDefaultProperty(e22);
  }, ao.selector = function(e22) {
    var t17 = "core" === e22 ? null : new Kr(e22), n13 = this.length++;
    return this[n13] = { selector: t17, properties: [], mappedProperties: [], index: n13 }, this;
  }, ao.css = function() {
    var e22 = arguments;
    if (1 === e22.length)
      for (var t17 = e22[0], n13 = 0; n13 < this.properties.length; n13++) {
        var r10 = this.properties[n13], a10 = t17[r10.name];
        void 0 === a10 && (a10 = t17[X4(r10.name)]), void 0 !== a10 && this.cssRule(r10.name, a10);
      }
    else
      2 === e22.length && this.cssRule(e22[0], e22[1]);
    return this;
  }, ao.style = ao.css, ao.cssRule = function(e22, t17) {
    var n13 = this.parse(e22, t17);
    if (n13) {
      var r10 = this.length - 1;
      this[r10].properties.push(n13), this[r10].properties[n13.name] = n13, n13.name.match(/pie-(\d+)-background-size/) && n13.value && (this._private.hasPie = true), n13.mapped && this[r10].mappedProperties.push(n13), !this[r10].selector && (this._private.coreStyle[n13.name] = n13);
    }
    return this;
  }, ao.append = function(e22) {
    return V5(e22) ? e22.appendToStyle(this) : _5(e22) ? this.appendFromJson(e22) : M6(e22) && this.appendFromString(e22), this;
  }, ro.fromJson = function(e22, t17) {
    var n13 = new ro(e22);
    return n13.fromJson(t17), n13;
  }, ro.fromString = function(e22, t17) {
    return new ro(e22).fromString(t17);
  }, [Gi, Zi, $i, Qi, Ji, eo, to, no].forEach(function(e22) {
    J4(ao, e22);
  }), ro.types = ao.types, ro.properties = ao.properties, ro.propertyGroups = ao.propertyGroups, ro.propertyGroupNames = ao.propertyGroupNames, ro.propertyGroupKeys = ao.propertyGroupKeys;
  var io = { style: function(e22) {
    e22 && this.setStyle(e22).update();
    return this._private.style;
  }, setStyle: function(e22) {
    var t17 = this._private;
    return V5(e22) ? t17.style = e22.generateStyle(this) : _5(e22) ? t17.style = ro.fromJson(this, e22) : M6(e22) ? t17.style = ro.fromString(this, e22) : t17.style = ro(this), t17.style;
  }, updateStyle: function() {
    this.mutableElements().updateStyle();
  } };
  var oo = { autolock: function(e22) {
    return void 0 === e22 ? this._private.autolock : (this._private.autolock = !!e22, this);
  }, autoungrabify: function(e22) {
    return void 0 === e22 ? this._private.autoungrabify : (this._private.autoungrabify = !!e22, this);
  }, autounselectify: function(e22) {
    return void 0 === e22 ? this._private.autounselectify : (this._private.autounselectify = !!e22, this);
  }, selectionType: function(e22) {
    var t17 = this._private;
    return null == t17.selectionType && (t17.selectionType = "single"), void 0 === e22 ? t17.selectionType : ("additive" !== e22 && "single" !== e22 || (t17.selectionType = e22), this);
  }, panningEnabled: function(e22) {
    return void 0 === e22 ? this._private.panningEnabled : (this._private.panningEnabled = !!e22, this);
  }, userPanningEnabled: function(e22) {
    return void 0 === e22 ? this._private.userPanningEnabled : (this._private.userPanningEnabled = !!e22, this);
  }, zoomingEnabled: function(e22) {
    return void 0 === e22 ? this._private.zoomingEnabled : (this._private.zoomingEnabled = !!e22, this);
  }, userZoomingEnabled: function(e22) {
    return void 0 === e22 ? this._private.userZoomingEnabled : (this._private.userZoomingEnabled = !!e22, this);
  }, boxSelectionEnabled: function(e22) {
    return void 0 === e22 ? this._private.boxSelectionEnabled : (this._private.boxSelectionEnabled = !!e22, this);
  }, pan: function() {
    var e22, t17, n13, r10, a10, i11 = arguments, o13 = this._private.pan;
    switch (i11.length) {
      case 0:
        return o13;
      case 1:
        if (M6(i11[0]))
          return o13[e22 = i11[0]];
        if (N6(i11[0])) {
          if (!this._private.panningEnabled)
            return this;
          r10 = (n13 = i11[0]).x, a10 = n13.y, I6(r10) && (o13.x = r10), I6(a10) && (o13.y = a10), this.emit("pan viewport");
        }
        break;
      case 2:
        if (!this._private.panningEnabled)
          return this;
        t17 = i11[1], "x" !== (e22 = i11[0]) && "y" !== e22 || !I6(t17) || (o13[e22] = t17), this.emit("pan viewport");
    }
    return this.notify("viewport"), this;
  }, panBy: function(e22, t17) {
    var n13, r10, a10, i11, o13, s11 = arguments, l11 = this._private.pan;
    if (!this._private.panningEnabled)
      return this;
    switch (s11.length) {
      case 1:
        N6(e22) && (i11 = (a10 = s11[0]).x, o13 = a10.y, I6(i11) && (l11.x += i11), I6(o13) && (l11.y += o13), this.emit("pan viewport"));
        break;
      case 2:
        r10 = t17, "x" !== (n13 = e22) && "y" !== n13 || !I6(r10) || (l11[n13] += r10), this.emit("pan viewport");
    }
    return this.notify("viewport"), this;
  }, fit: function(e22, t17) {
    var n13 = this.getFitViewport(e22, t17);
    if (n13) {
      var r10 = this._private;
      r10.zoom = n13.zoom, r10.pan = n13.pan, this.emit("pan zoom viewport"), this.notify("viewport");
    }
    return this;
  }, getFitViewport: function(e22, t17) {
    if (I6(e22) && void 0 === t17 && (t17 = e22, e22 = void 0), this._private.panningEnabled && this._private.zoomingEnabled) {
      var n13, r10;
      if (M6(e22)) {
        var a10 = e22;
        e22 = this.$(a10);
      } else if (N6(r10 = e22) && I6(r10.x1) && I6(r10.x2) && I6(r10.y1) && I6(r10.y2)) {
        var i11 = e22;
        (n13 = { x1: i11.x1, y1: i11.y1, x2: i11.x2, y2: i11.y2 }).w = n13.x2 - n13.x1, n13.h = n13.y2 - n13.y1;
      } else
        L5(e22) || (e22 = this.mutableElements());
      if (!L5(e22) || !e22.empty()) {
        n13 = n13 || e22.boundingBox();
        var o13, s11 = this.width(), l11 = this.height();
        if (t17 = I6(t17) ? t17 : 0, !isNaN(s11) && !isNaN(l11) && s11 > 0 && l11 > 0 && !isNaN(n13.w) && !isNaN(n13.h) && n13.w > 0 && n13.h > 0)
          return { zoom: o13 = (o13 = (o13 = Math.min((s11 - 2 * t17) / n13.w, (l11 - 2 * t17) / n13.h)) > this._private.maxZoom ? this._private.maxZoom : o13) < this._private.minZoom ? this._private.minZoom : o13, pan: { x: (s11 - o13 * (n13.x1 + n13.x2)) / 2, y: (l11 - o13 * (n13.y1 + n13.y2)) / 2 } };
      }
    }
  }, zoomRange: function(e22, t17) {
    var n13 = this._private;
    if (null == t17) {
      var r10 = e22;
      e22 = r10.min, t17 = r10.max;
    }
    return I6(e22) && I6(t17) && e22 <= t17 ? (n13.minZoom = e22, n13.maxZoom = t17) : I6(e22) && void 0 === t17 && e22 <= n13.maxZoom ? n13.minZoom = e22 : I6(t17) && void 0 === e22 && t17 >= n13.minZoom && (n13.maxZoom = t17), this;
  }, minZoom: function(e22) {
    return void 0 === e22 ? this._private.minZoom : this.zoomRange({ min: e22 });
  }, maxZoom: function(e22) {
    return void 0 === e22 ? this._private.maxZoom : this.zoomRange({ max: e22 });
  }, getZoomedViewport: function(e22) {
    var t17, n13, r10 = this._private, a10 = r10.pan, i11 = r10.zoom, o13 = false;
    if (r10.zoomingEnabled || (o13 = true), I6(e22) ? n13 = e22 : N6(e22) && (n13 = e22.level, null != e22.position ? t17 = at4(e22.position, i11, a10) : null != e22.renderedPosition && (t17 = e22.renderedPosition), null == t17 || r10.panningEnabled || (o13 = true)), n13 = (n13 = n13 > r10.maxZoom ? r10.maxZoom : n13) < r10.minZoom ? r10.minZoom : n13, o13 || !I6(n13) || n13 === i11 || null != t17 && (!I6(t17.x) || !I6(t17.y)))
      return null;
    if (null != t17) {
      var s11 = a10, l11 = i11, u10 = n13;
      return { zoomed: true, panned: true, zoom: u10, pan: { x: -u10 / l11 * (t17.x - s11.x) + t17.x, y: -u10 / l11 * (t17.y - s11.y) + t17.y } };
    }
    return { zoomed: true, panned: false, zoom: n13, pan: a10 };
  }, zoom: function(e22) {
    if (void 0 === e22)
      return this._private.zoom;
    var t17 = this.getZoomedViewport(e22), n13 = this._private;
    return null != t17 && t17.zoomed ? (n13.zoom = t17.zoom, t17.panned && (n13.pan.x = t17.pan.x, n13.pan.y = t17.pan.y), this.emit("zoom" + (t17.panned ? " pan" : "") + " viewport"), this.notify("viewport"), this) : this;
  }, viewport: function(e22) {
    var t17 = this._private, n13 = true, r10 = true, a10 = [], i11 = false, o13 = false;
    if (!e22)
      return this;
    if (I6(e22.zoom) || (n13 = false), N6(e22.pan) || (r10 = false), !n13 && !r10)
      return this;
    if (n13) {
      var s11 = e22.zoom;
      s11 < t17.minZoom || s11 > t17.maxZoom || !t17.zoomingEnabled ? i11 = true : (t17.zoom = s11, a10.push("zoom"));
    }
    if (r10 && (!i11 || !e22.cancelOnFailedZoom) && t17.panningEnabled) {
      var l11 = e22.pan;
      I6(l11.x) && (t17.pan.x = l11.x, o13 = false), I6(l11.y) && (t17.pan.y = l11.y, o13 = false), o13 || a10.push("pan");
    }
    return a10.length > 0 && (a10.push("viewport"), this.emit(a10.join(" ")), this.notify("viewport")), this;
  }, center: function(e22) {
    var t17 = this.getCenterPan(e22);
    return t17 && (this._private.pan = t17, this.emit("pan viewport"), this.notify("viewport")), this;
  }, getCenterPan: function(e22, t17) {
    if (this._private.panningEnabled) {
      if (M6(e22)) {
        var n13 = e22;
        e22 = this.mutableElements().filter(n13);
      } else
        L5(e22) || (e22 = this.mutableElements());
      if (0 !== e22.length) {
        var r10 = e22.boundingBox(), a10 = this.width(), i11 = this.height();
        return { x: (a10 - (t17 = void 0 === t17 ? this._private.zoom : t17) * (r10.x1 + r10.x2)) / 2, y: (i11 - t17 * (r10.y1 + r10.y2)) / 2 };
      }
    }
  }, reset: function() {
    return this._private.panningEnabled && this._private.zoomingEnabled ? (this.viewport({ pan: { x: 0, y: 0 }, zoom: 1 }), this) : this;
  }, invalidateSize: function() {
    this._private.sizeCache = null;
  }, size: function() {
    var e22, t17, n13 = this._private, r10 = n13.container, a10 = this;
    return n13.sizeCache = n13.sizeCache || (r10 ? (e22 = a10.window().getComputedStyle(r10), t17 = function(t18) {
      return parseFloat(e22.getPropertyValue(t18));
    }, { width: r10.clientWidth - t17("padding-left") - t17("padding-right"), height: r10.clientHeight - t17("padding-top") - t17("padding-bottom") }) : { width: 1, height: 1 });
  }, width: function() {
    return this.size().width;
  }, height: function() {
    return this.size().height;
  }, extent: function() {
    var e22 = this._private.pan, t17 = this._private.zoom, n13 = this.renderedExtent(), r10 = { x1: (n13.x1 - e22.x) / t17, x2: (n13.x2 - e22.x) / t17, y1: (n13.y1 - e22.y) / t17, y2: (n13.y2 - e22.y) / t17 };
    return r10.w = r10.x2 - r10.x1, r10.h = r10.y2 - r10.y1, r10;
  }, renderedExtent: function() {
    var e22 = this.width(), t17 = this.height();
    return { x1: 0, y1: 0, x2: e22, y2: t17, w: e22, h: t17 };
  }, multiClickDebounceTime: function(e22) {
    return e22 ? (this._private.multiClickDebounceTime = e22, this) : this._private.multiClickDebounceTime;
  } };
  oo.centre = oo.center, oo.autolockNodes = oo.autolock, oo.autoungrabifyNodes = oo.autoungrabify;
  var so = { data: ur3.data({ field: "data", bindingEvent: "data", allowBinding: true, allowSetting: true, settingEvent: "data", settingTriggersEvent: true, triggerFnName: "trigger", allowGetting: true, updateStyle: true }), removeData: ur3.removeData({ field: "data", event: "data", triggerFnName: "trigger", triggerEvent: true, updateStyle: true }), scratch: ur3.data({ field: "scratch", bindingEvent: "scratch", allowBinding: true, allowSetting: true, settingEvent: "scratch", settingTriggersEvent: true, triggerFnName: "trigger", allowGetting: true, updateStyle: true }), removeScratch: ur3.removeData({ field: "scratch", event: "scratch", triggerFnName: "trigger", triggerEvent: true, updateStyle: true }) };
  so.attr = so.data, so.removeAttr = so.removeData;
  var lo = function(e22) {
    var t17 = this, n13 = (e22 = J4({}, e22)).container;
    n13 && !z5(n13) && z5(n13[0]) && (n13 = n13[0]);
    var r10 = n13 ? n13._cyreg : null;
    (r10 = r10 || {}) && r10.cy && (r10.cy.destroy(), r10 = {});
    var a10 = r10.readies = r10.readies || [];
    n13 && (n13._cyreg = r10), r10.cy = t17;
    var i11 = void 0 !== E6 && void 0 !== n13 && !e22.headless, o13 = e22;
    o13.layout = J4({ name: i11 ? "grid" : "null" }, o13.layout), o13.renderer = J4({ name: i11 ? "canvas" : "null" }, o13.renderer);
    var s11 = function(e23, t18, n14) {
      return void 0 !== t18 ? t18 : void 0 !== n14 ? n14 : e23;
    }, l11 = this._private = { container: n13, ready: false, options: o13, elements: new Ci(this), listeners: [], aniEles: new Ci(this), data: o13.data || {}, scratch: {}, layout: null, renderer: null, destroyed: false, notificationsEnabled: true, minZoom: 1e-50, maxZoom: 1e50, zoomingEnabled: s11(true, o13.zoomingEnabled), userZoomingEnabled: s11(true, o13.userZoomingEnabled), panningEnabled: s11(true, o13.panningEnabled), userPanningEnabled: s11(true, o13.userPanningEnabled), boxSelectionEnabled: s11(true, o13.boxSelectionEnabled), autolock: s11(false, o13.autolock, o13.autolockNodes), autoungrabify: s11(false, o13.autoungrabify, o13.autoungrabifyNodes), autounselectify: s11(false, o13.autounselectify), styleEnabled: void 0 === o13.styleEnabled ? i11 : o13.styleEnabled, zoom: I6(o13.zoom) ? o13.zoom : 1, pan: { x: N6(o13.pan) && I6(o13.pan.x) ? o13.pan.x : 0, y: N6(o13.pan) && I6(o13.pan.y) ? o13.pan.y : 0 }, animation: { current: [], queue: [] }, hasCompoundNodes: false, multiClickDebounceTime: s11(250, o13.multiClickDebounceTime) };
    this.createEmitter(), this.selectionType(o13.selectionType), this.zoomRange({ min: o13.minZoom, max: o13.maxZoom });
    l11.styleEnabled && t17.setStyle([]);
    var u10 = J4({}, o13, o13.renderer);
    t17.initRenderer(u10);
    !function(e23, t18) {
      if (e23.some(q5))
        return rr4.all(e23).then(t18);
      t18(e23);
    }([o13.style, o13.elements], function(e23) {
      var n14 = e23[0], i12 = e23[1];
      l11.styleEnabled && t17.style().append(n14), function(e24, n15, r11) {
        t17.notifications(false);
        var a11 = t17.mutableElements();
        a11.length > 0 && a11.remove(), null != e24 && (N6(e24) || _5(e24)) && t17.add(e24), t17.one("layoutready", function(e25) {
          t17.notifications(true), t17.emit(e25), t17.one("load", n15), t17.emitAndNotify("load");
        }).one("layoutstop", function() {
          t17.one("done", r11), t17.emit("done");
        });
        var i13 = J4({}, t17._private.options.layout);
        i13.eles = t17.elements(), t17.layout(i13).run();
      }(i12, function() {
        t17.startAnimationLoop(), l11.ready = true, B4(o13.ready) && t17.on("ready", o13.ready);
        for (var e24 = 0; e24 < a10.length; e24++) {
          var n15 = a10[e24];
          t17.on("ready", n15);
        }
        r10 && (r10.readies = []), t17.emit("ready");
      }, o13.done);
    });
  };
  var uo = lo.prototype;
  J4(uo, { instanceString: function() {
    return "core";
  }, isReady: function() {
    return this._private.ready;
  }, destroyed: function() {
    return this._private.destroyed;
  }, ready: function(e22) {
    return this.isReady() ? this.emitter().emit("ready", [], e22) : this.on("ready", e22), this;
  }, destroy: function() {
    var e22 = this;
    if (!e22.destroyed())
      return e22.stopAnimationLoop(), e22.destroyRenderer(), this.emit("destroy"), e22._private.destroyed = true, e22;
  }, hasElementWithId: function(e22) {
    return this._private.elements.hasElementWithId(e22);
  }, getElementById: function(e22) {
    return this._private.elements.getElementById(e22);
  }, hasCompoundNodes: function() {
    return this._private.hasCompoundNodes;
  }, headless: function() {
    return this._private.renderer.isHeadless();
  }, styleEnabled: function() {
    return this._private.styleEnabled;
  }, addToPool: function(e22) {
    return this._private.elements.merge(e22), this;
  }, removeFromPool: function(e22) {
    return this._private.elements.unmerge(e22), this;
  }, container: function() {
    return this._private.container || null;
  }, window: function() {
    if (null == this._private.container)
      return E6;
    var e22 = this._private.container.ownerDocument;
    return void 0 === e22 || null == e22 ? E6 : e22.defaultView || E6;
  }, mount: function(e22) {
    if (null != e22) {
      var t17 = this, n13 = t17._private, r10 = n13.options;
      return !z5(e22) && z5(e22[0]) && (e22 = e22[0]), t17.stopAnimationLoop(), t17.destroyRenderer(), n13.container = e22, n13.styleEnabled = true, t17.invalidateSize(), t17.initRenderer(J4({}, r10, r10.renderer, { name: "null" === r10.renderer.name ? "canvas" : r10.renderer.name })), t17.startAnimationLoop(), t17.style(r10.style), t17.emit("mount"), t17;
    }
  }, unmount: function() {
    var e22 = this;
    return e22.stopAnimationLoop(), e22.destroyRenderer(), e22.initRenderer({ name: "null" }), e22.emit("unmount"), e22;
  }, options: function() {
    return Be(this._private.options);
  }, json: function(e22) {
    var t17 = this, n13 = t17._private, r10 = t17.mutableElements();
    if (N6(e22)) {
      if (t17.startBatch(), e22.elements) {
        var a10 = {}, i11 = function(e23, n14) {
          for (var r11 = [], i12 = [], o14 = 0; o14 < e23.length; o14++) {
            var s12 = e23[o14];
            if (s12.data.id) {
              var l12 = "" + s12.data.id, u11 = t17.getElementById(l12);
              a10[l12] = true, 0 !== u11.length ? i12.push({ ele: u11, json: s12 }) : n14 ? (s12.group = n14, r11.push(s12)) : r11.push(s12);
            } else
              Me("cy.json() cannot handle elements without an ID attribute");
          }
          t17.add(r11);
          for (var c11 = 0; c11 < i12.length; c11++) {
            var d13 = i12[c11], h11 = d13.ele, p11 = d13.json;
            h11.json(p11);
          }
        };
        if (_5(e22.elements))
          i11(e22.elements);
        else
          for (var o13 = ["nodes", "edges"], s11 = 0; s11 < o13.length; s11++) {
            var l11 = o13[s11], u10 = e22.elements[l11];
            _5(u10) && i11(u10, l11);
          }
        var c10 = t17.collection();
        r10.filter(function(e23) {
          return !a10[e23.id()];
        }).forEach(function(e23) {
          e23.isParent() ? c10.merge(e23) : e23.remove();
        }), c10.forEach(function(e23) {
          return e23.children().move({ parent: null });
        }), c10.forEach(function(e23) {
          return function(e24) {
            return t17.getElementById(e24.id());
          }(e23).remove();
        });
      }
      e22.style && t17.style(e22.style), null != e22.zoom && e22.zoom !== n13.zoom && t17.zoom(e22.zoom), e22.pan && (e22.pan.x === n13.pan.x && e22.pan.y === n13.pan.y || t17.pan(e22.pan)), e22.data && t17.data(e22.data);
      for (var d12 = ["minZoom", "maxZoom", "zoomingEnabled", "userZoomingEnabled", "panningEnabled", "userPanningEnabled", "boxSelectionEnabled", "autolock", "autoungrabify", "autounselectify", "multiClickDebounceTime"], h10 = 0; h10 < d12.length; h10++) {
        var p10 = d12[h10];
        null != e22[p10] && t17[p10](e22[p10]);
      }
      return t17.endBatch(), this;
    }
    var f11 = {};
    !!e22 ? f11.elements = this.elements().map(function(e23) {
      return e23.json();
    }) : (f11.elements = {}, r10.forEach(function(e23) {
      var t18 = e23.group();
      f11.elements[t18] || (f11.elements[t18] = []), f11.elements[t18].push(e23.json());
    })), this._private.styleEnabled && (f11.style = t17.style().json()), f11.data = Be(t17.data());
    var g9 = n13.options;
    return f11.zoomingEnabled = n13.zoomingEnabled, f11.userZoomingEnabled = n13.userZoomingEnabled, f11.zoom = n13.zoom, f11.minZoom = n13.minZoom, f11.maxZoom = n13.maxZoom, f11.panningEnabled = n13.panningEnabled, f11.userPanningEnabled = n13.userPanningEnabled, f11.pan = Be(n13.pan), f11.boxSelectionEnabled = n13.boxSelectionEnabled, f11.renderer = Be(g9.renderer), f11.hideEdgesOnViewport = g9.hideEdgesOnViewport, f11.textureOnViewport = g9.textureOnViewport, f11.wheelSensitivity = g9.wheelSensitivity, f11.motionBlur = g9.motionBlur, f11.multiClickDebounceTime = g9.multiClickDebounceTime, f11;
  } }), uo.$id = uo.getElementById, [Di, Ri, qi, ji, Yi, Xi, Hi, Ki, io, oo, so].forEach(function(e22) {
    J4(uo, e22);
  });
  var co = { fit: true, directed: false, padding: 30, circle: false, grid: false, spacingFactor: 1.75, boundingBox: void 0, avoidOverlap: true, nodeDimensionsIncludeLabels: false, roots: void 0, depthSort: void 0, animate: false, animationDuration: 500, animationEasing: void 0, animateFilter: function(e22, t17) {
    return true;
  }, ready: void 0, stop: void 0, transform: function(e22, t17) {
    return t17;
  } };
  var ho = { maximal: false, acyclic: false };
  var po = function(e22) {
    return e22.scratch("breadthfirst");
  };
  var fo = function(e22, t17) {
    return e22.scratch("breadthfirst", t17);
  };
  function go(e22) {
    this.options = J4({}, co, ho, e22);
  }
  go.prototype.run = function() {
    var e22, t17 = this.options, n13 = t17, r10 = t17.cy, a10 = n13.eles, i11 = a10.nodes().filter(function(e23) {
      return !e23.isParent();
    }), o13 = a10, s11 = n13.directed, l11 = n13.acyclic || n13.maximal || n13.maximalAdjustments > 0, u10 = vt4(n13.boundingBox ? n13.boundingBox : { x1: 0, y1: 0, w: r10.width(), h: r10.height() });
    if (L5(n13.roots))
      e22 = n13.roots;
    else if (_5(n13.roots)) {
      for (var c10 = [], d12 = 0; d12 < n13.roots.length; d12++) {
        var h10 = n13.roots[d12], p10 = r10.getElementById(h10);
        c10.push(p10);
      }
      e22 = r10.collection(c10);
    } else if (M6(n13.roots))
      e22 = r10.$(n13.roots);
    else if (s11)
      e22 = i11.roots();
    else {
      var f11 = a10.components();
      e22 = r10.collection();
      for (var g9 = function(t18) {
        var n14 = f11[t18], r11 = n14.maxDegree(false), a11 = n14.filter(function(e23) {
          return e23.degree(false) === r11;
        });
        e22 = e22.add(a11);
      }, v12 = 0; v12 < f11.length; v12++)
        g9(v12);
    }
    var y10 = [], m12 = {}, b11 = function(e23, t18) {
      null == y10[t18] && (y10[t18] = []);
      var n14 = y10[t18].length;
      y10[t18].push(e23), fo(e23, { index: n14, depth: t18 });
    };
    o13.bfs({ roots: e22, directed: n13.directed, visit: function(e23, t18, n14, r11, a11) {
      var i12 = e23[0], o14 = i12.id();
      b11(i12, a11), m12[o14] = true;
    } });
    for (var x11 = [], w10 = 0; w10 < i11.length; w10++) {
      var E10 = i11[w10];
      m12[E10.id()] || x11.push(E10);
    }
    var k10 = function(e23) {
      for (var t18 = y10[e23], n14 = 0; n14 < t18.length; n14++) {
        var r11 = t18[n14];
        null != r11 ? fo(r11, { depth: e23, index: n14 }) : (t18.splice(n14, 1), n14--);
      }
    }, C9 = function() {
      for (var e23 = 0; e23 < y10.length; e23++)
        k10(e23);
    }, S8 = function(e23, t18) {
      for (var r11 = po(e23), i12 = e23.incomers().filter(function(e24) {
        return e24.isNode() && a10.has(e24);
      }), o14 = -1, s12 = e23.id(), l12 = 0; l12 < i12.length; l12++) {
        var u11 = i12[l12], c11 = po(u11);
        o14 = Math.max(o14, c11.depth);
      }
      if (r11.depth <= o14) {
        if (!n13.acyclic && t18[s12])
          return null;
        var d13 = o14 + 1;
        return function(e24, t19) {
          var n14 = po(e24), r12 = n14.depth, a11 = n14.index;
          y10[r12][a11] = null, b11(e24, t19);
        }(e23, d13), t18[s12] = d13, true;
      }
      return false;
    };
    if (s11 && l11) {
      var D7 = [], P10 = {}, T9 = function(e23) {
        return D7.push(e23);
      };
      for (i11.forEach(function(e23) {
        return D7.push(e23);
      }); D7.length > 0; ) {
        var B8 = D7.shift(), N8 = S8(B8, P10);
        if (N8)
          B8.outgoers().filter(function(e23) {
            return e23.isNode() && a10.has(e23);
          }).forEach(T9);
        else if (null === N8) {
          Me("Detected double maximal shift for node `" + B8.id() + "`.  Bailing maximal adjustment due to cycle.  Use `options.maximal: true` only on DAGs.");
          break;
        }
      }
    }
    C9();
    var I8 = 0;
    if (n13.avoidOverlap)
      for (var z8 = 0; z8 < i11.length; z8++) {
        var A10 = i11[z8].layoutDimensions(n13), O9 = A10.w, R8 = A10.h;
        I8 = Math.max(I8, O9, R8);
      }
    var V8 = {}, F9 = function(e23) {
      if (V8[e23.id()])
        return V8[e23.id()];
      for (var t18 = po(e23).depth, n14 = e23.neighborhood(), r11 = 0, a11 = 0, o14 = 0; o14 < n14.length; o14++) {
        var s12 = n14[o14];
        if (!s12.isEdge() && !s12.isParent() && i11.has(s12)) {
          var l12 = po(s12);
          if (null != l12) {
            var u11 = l12.index, c11 = l12.depth;
            if (null != u11 && null != c11) {
              var d13 = y10[c11].length;
              c11 < t18 && (r11 += u11 / d13, a11++);
            }
          }
        }
      }
      return r11 /= a11 = Math.max(1, a11), 0 === a11 && (r11 = 0), V8[e23.id()] = r11, r11;
    }, q8 = function(e23, t18) {
      var n14 = F9(e23) - F9(t18);
      return 0 === n14 ? Q4(e23.id(), t18.id()) : n14;
    };
    void 0 !== n13.depthSort && (q8 = n13.depthSort);
    for (var j9 = 0; j9 < y10.length; j9++)
      y10[j9].sort(q8), k10(j9);
    for (var Y6 = [], X6 = 0; X6 < x11.length; X6++)
      Y6.push(x11[X6]);
    y10.unshift(Y6), C9();
    for (var W8 = 0, H8 = 0; H8 < y10.length; H8++)
      W8 = Math.max(y10[H8].length, W8);
    var K6 = u10.x1 + u10.w / 2, G6 = u10.x1 + u10.h / 2, U7 = y10.reduce(function(e23, t18) {
      return Math.max(e23, t18.length);
    }, 0);
    return a10.nodes().layoutPositions(this, n13, function(e23) {
      var t18 = po(e23), r11 = t18.depth, a11 = t18.index, i12 = y10[r11].length, o14 = Math.max(u10.w / ((n13.grid ? U7 : i12) + 1), I8), s12 = Math.max(u10.h / (y10.length + 1), I8), l12 = Math.min(u10.w / 2 / y10.length, u10.h / 2 / y10.length);
      if (l12 = Math.max(l12, I8), n13.circle) {
        var c11 = l12 * r11 + l12 - (y10.length > 0 && y10[0].length <= 3 ? l12 / 2 : 0), d13 = 2 * Math.PI / y10[r11].length * a11;
        return 0 === r11 && 1 === y10[0].length && (c11 = 1), { x: K6 + c11 * Math.cos(d13), y: G6 + c11 * Math.sin(d13) };
      }
      return { x: K6 + (a11 + 1 - (i12 + 1) / 2) * o14, y: (r11 + 1) * s12 };
    }), this;
  };
  var vo = { fit: true, padding: 30, boundingBox: void 0, avoidOverlap: true, nodeDimensionsIncludeLabels: false, spacingFactor: void 0, radius: void 0, startAngle: 1.5 * Math.PI, sweep: void 0, clockwise: true, sort: void 0, animate: false, animationDuration: 500, animationEasing: void 0, animateFilter: function(e22, t17) {
    return true;
  }, ready: void 0, stop: void 0, transform: function(e22, t17) {
    return t17;
  } };
  function yo(e22) {
    this.options = J4({}, vo, e22);
  }
  yo.prototype.run = function() {
    var e22 = this.options, t17 = e22, n13 = e22.cy, r10 = t17.eles, a10 = void 0 !== t17.counterclockwise ? !t17.counterclockwise : t17.clockwise, i11 = r10.nodes().not(":parent");
    t17.sort && (i11 = i11.sort(t17.sort));
    for (var o13, s11 = vt4(t17.boundingBox ? t17.boundingBox : { x1: 0, y1: 0, w: n13.width(), h: n13.height() }), l11 = s11.x1 + s11.w / 2, u10 = s11.y1 + s11.h / 2, c10 = (void 0 === t17.sweep ? 2 * Math.PI - 2 * Math.PI / i11.length : t17.sweep) / Math.max(1, i11.length - 1), d12 = 0, h10 = 0; h10 < i11.length; h10++) {
      var p10 = i11[h10].layoutDimensions(t17), f11 = p10.w, g9 = p10.h;
      d12 = Math.max(d12, f11, g9);
    }
    if (o13 = I6(t17.radius) ? t17.radius : i11.length <= 1 ? 0 : Math.min(s11.h, s11.w) / 2 - d12, i11.length > 1 && t17.avoidOverlap) {
      d12 *= 1.75;
      var v12 = Math.cos(c10) - Math.cos(0), y10 = Math.sin(c10) - Math.sin(0), m12 = Math.sqrt(d12 * d12 / (v12 * v12 + y10 * y10));
      o13 = Math.max(m12, o13);
    }
    return r10.nodes().layoutPositions(this, t17, function(e23, n14) {
      var r11 = t17.startAngle + n14 * c10 * (a10 ? 1 : -1), i12 = o13 * Math.cos(r11), s12 = o13 * Math.sin(r11);
      return { x: l11 + i12, y: u10 + s12 };
    }), this;
  };
  var mo;
  var bo = { fit: true, padding: 30, startAngle: 1.5 * Math.PI, sweep: void 0, clockwise: true, equidistant: false, minNodeSpacing: 10, boundingBox: void 0, avoidOverlap: true, nodeDimensionsIncludeLabels: false, height: void 0, width: void 0, spacingFactor: void 0, concentric: function(e22) {
    return e22.degree();
  }, levelWidth: function(e22) {
    return e22.maxDegree() / 4;
  }, animate: false, animationDuration: 500, animationEasing: void 0, animateFilter: function(e22, t17) {
    return true;
  }, ready: void 0, stop: void 0, transform: function(e22, t17) {
    return t17;
  } };
  function xo(e22) {
    this.options = J4({}, bo, e22);
  }
  xo.prototype.run = function() {
    for (var e22 = this.options, t17 = e22, n13 = void 0 !== t17.counterclockwise ? !t17.counterclockwise : t17.clockwise, r10 = e22.cy, a10 = t17.eles, i11 = a10.nodes().not(":parent"), o13 = vt4(t17.boundingBox ? t17.boundingBox : { x1: 0, y1: 0, w: r10.width(), h: r10.height() }), s11 = o13.x1 + o13.w / 2, l11 = o13.y1 + o13.h / 2, u10 = [], c10 = 0, d12 = 0; d12 < i11.length; d12++) {
      var h10, p10 = i11[d12];
      h10 = t17.concentric(p10), u10.push({ value: h10, node: p10 }), p10._private.scratch.concentric = h10;
    }
    i11.updateStyle();
    for (var f11 = 0; f11 < i11.length; f11++) {
      var g9 = i11[f11].layoutDimensions(t17);
      c10 = Math.max(c10, g9.w, g9.h);
    }
    u10.sort(function(e23, t18) {
      return t18.value - e23.value;
    });
    for (var v12 = t17.levelWidth(i11), y10 = [[]], m12 = y10[0], b11 = 0; b11 < u10.length; b11++) {
      var x11 = u10[b11];
      if (m12.length > 0)
        Math.abs(m12[0].value - x11.value) >= v12 && (m12 = [], y10.push(m12));
      m12.push(x11);
    }
    var w10 = c10 + t17.minNodeSpacing;
    if (!t17.avoidOverlap) {
      var E10 = y10.length > 0 && y10[0].length > 1, k10 = (Math.min(o13.w, o13.h) / 2 - w10) / (y10.length + E10 ? 1 : 0);
      w10 = Math.min(w10, k10);
    }
    for (var C9 = 0, S8 = 0; S8 < y10.length; S8++) {
      var D7 = y10[S8], P10 = void 0 === t17.sweep ? 2 * Math.PI - 2 * Math.PI / D7.length : t17.sweep, T9 = D7.dTheta = P10 / Math.max(1, D7.length - 1);
      if (D7.length > 1 && t17.avoidOverlap) {
        var M9 = Math.cos(T9) - Math.cos(0), B8 = Math.sin(T9) - Math.sin(0), _7 = Math.sqrt(w10 * w10 / (M9 * M9 + B8 * B8));
        C9 = Math.max(_7, C9);
      }
      D7.r = C9, C9 += w10;
    }
    if (t17.equidistant) {
      for (var N8 = 0, I8 = 0, z8 = 0; z8 < y10.length; z8++) {
        var L10 = y10[z8].r - I8;
        N8 = Math.max(N8, L10);
      }
      I8 = 0;
      for (var A10 = 0; A10 < y10.length; A10++) {
        var O9 = y10[A10];
        0 === A10 && (I8 = O9.r), O9.r = I8, I8 += N8;
      }
    }
    for (var R8 = {}, V8 = 0; V8 < y10.length; V8++)
      for (var F9 = y10[V8], q8 = F9.dTheta, j9 = F9.r, Y6 = 0; Y6 < F9.length; Y6++) {
        var X6 = F9[Y6], W8 = t17.startAngle + (n13 ? 1 : -1) * q8 * Y6, H8 = { x: s11 + j9 * Math.cos(W8), y: l11 + j9 * Math.sin(W8) };
        R8[X6.node.id()] = H8;
      }
    return a10.nodes().layoutPositions(this, t17, function(e23) {
      var t18 = e23.id();
      return R8[t18];
    }), this;
  };
  var wo = { ready: function() {
  }, stop: function() {
  }, animate: true, animationEasing: void 0, animationDuration: void 0, animateFilter: function(e22, t17) {
    return true;
  }, animationThreshold: 250, refresh: 20, fit: true, padding: 30, boundingBox: void 0, nodeDimensionsIncludeLabels: false, randomize: false, componentSpacing: 40, nodeRepulsion: function(e22) {
    return 2048;
  }, nodeOverlap: 4, idealEdgeLength: function(e22) {
    return 32;
  }, edgeElasticity: function(e22) {
    return 32;
  }, nestingFactor: 1.2, gravity: 1, numIter: 1e3, initialTemp: 1e3, coolingFactor: 0.99, minTemp: 1 };
  function Eo(e22) {
    this.options = J4({}, wo, e22), this.options.layout = this;
  }
  Eo.prototype.run = function() {
    var e22 = this.options, t17 = e22.cy, n13 = this;
    n13.stopped = false, true !== e22.animate && false !== e22.animate || n13.emit({ type: "layoutstart", layout: n13 }), mo = true === e22.debug;
    var r10 = ko(t17, n13, e22);
    mo && (void 0)(r10), e22.randomize && Do(r10);
    var a10 = le(), i11 = function() {
      To(r10, t17, e22), true === e22.fit && t17.fit(e22.padding);
    }, o13 = function(t18) {
      return !(n13.stopped || t18 >= e22.numIter) && (Mo(r10, e22), r10.temperature = r10.temperature * e22.coolingFactor, !(r10.temperature < e22.minTemp));
    }, s11 = function() {
      if (true === e22.animate || false === e22.animate)
        i11(), n13.one("layoutstop", e22.stop), n13.emit({ type: "layoutstop", layout: n13 });
      else {
        var t18 = e22.eles.nodes(), a11 = Po(r10, e22, t18);
        t18.layoutPositions(n13, e22, a11);
      }
    }, l11 = 0, u10 = true;
    if (true === e22.animate) {
      !function t18() {
        for (var n14 = 0; u10 && n14 < e22.refresh; )
          u10 = o13(l11), l11++, n14++;
        u10 ? (le() - a10 >= e22.animationThreshold && i11(), se(t18)) : (qo(r10, e22), s11());
      }();
    } else {
      for (; u10; )
        u10 = o13(l11), l11++;
      qo(r10, e22), s11();
    }
    return this;
  }, Eo.prototype.stop = function() {
    return this.stopped = true, this.thread && this.thread.stop(), this.emit("layoutstop"), this;
  }, Eo.prototype.destroy = function() {
    return this.thread && this.thread.stop(), this;
  };
  var ko = function(e22, t17, n13) {
    for (var r10 = n13.eles.edges(), a10 = n13.eles.nodes(), i11 = vt4(n13.boundingBox ? n13.boundingBox : { x1: 0, y1: 0, w: e22.width(), h: e22.height() }), o13 = { isCompound: e22.hasCompoundNodes(), layoutNodes: [], idToIndex: {}, nodeSize: a10.size(), graphSet: [], indexToGraph: [], layoutEdges: [], edgeSize: r10.size(), temperature: n13.initialTemp, clientWidth: i11.w, clientHeight: i11.h, boundingBox: i11 }, s11 = n13.eles.components(), l11 = {}, u10 = 0; u10 < s11.length; u10++)
      for (var c10 = s11[u10], d12 = 0; d12 < c10.length; d12++) {
        l11[c10[d12].id()] = u10;
      }
    for (u10 = 0; u10 < o13.nodeSize; u10++) {
      var h10 = (y10 = a10[u10]).layoutDimensions(n13);
      (z8 = {}).isLocked = y10.locked(), z8.id = y10.data("id"), z8.parentId = y10.data("parent"), z8.cmptId = l11[y10.id()], z8.children = [], z8.positionX = y10.position("x"), z8.positionY = y10.position("y"), z8.offsetX = 0, z8.offsetY = 0, z8.height = h10.w, z8.width = h10.h, z8.maxX = z8.positionX + z8.width / 2, z8.minX = z8.positionX - z8.width / 2, z8.maxY = z8.positionY + z8.height / 2, z8.minY = z8.positionY - z8.height / 2, z8.padLeft = parseFloat(y10.style("padding")), z8.padRight = parseFloat(y10.style("padding")), z8.padTop = parseFloat(y10.style("padding")), z8.padBottom = parseFloat(y10.style("padding")), z8.nodeRepulsion = B4(n13.nodeRepulsion) ? n13.nodeRepulsion(y10) : n13.nodeRepulsion, o13.layoutNodes.push(z8), o13.idToIndex[z8.id] = u10;
    }
    var p10 = [], f11 = 0, g9 = -1, v12 = [];
    for (u10 = 0; u10 < o13.nodeSize; u10++) {
      var y10, m12 = (y10 = o13.layoutNodes[u10]).parentId;
      null != m12 ? o13.layoutNodes[o13.idToIndex[m12]].children.push(y10.id) : (p10[++g9] = y10.id, v12.push(y10.id));
    }
    for (o13.graphSet.push(v12); f11 <= g9; ) {
      var b11 = p10[f11++], x11 = o13.idToIndex[b11], w10 = o13.layoutNodes[x11].children;
      if (w10.length > 0) {
        o13.graphSet.push(w10);
        for (u10 = 0; u10 < w10.length; u10++)
          p10[++g9] = w10[u10];
      }
    }
    for (u10 = 0; u10 < o13.graphSet.length; u10++) {
      var E10 = o13.graphSet[u10];
      for (d12 = 0; d12 < E10.length; d12++) {
        var k10 = o13.idToIndex[E10[d12]];
        o13.indexToGraph[k10] = u10;
      }
    }
    for (u10 = 0; u10 < o13.edgeSize; u10++) {
      var C9 = r10[u10], S8 = {};
      S8.id = C9.data("id"), S8.sourceId = C9.data("source"), S8.targetId = C9.data("target");
      var D7 = B4(n13.idealEdgeLength) ? n13.idealEdgeLength(C9) : n13.idealEdgeLength, P10 = B4(n13.edgeElasticity) ? n13.edgeElasticity(C9) : n13.edgeElasticity, T9 = o13.idToIndex[S8.sourceId], M9 = o13.idToIndex[S8.targetId];
      if (o13.indexToGraph[T9] != o13.indexToGraph[M9]) {
        for (var _7 = Co(S8.sourceId, S8.targetId, o13), N8 = o13.graphSet[_7], I8 = 0, z8 = o13.layoutNodes[T9]; -1 === N8.indexOf(z8.id); )
          z8 = o13.layoutNodes[o13.idToIndex[z8.parentId]], I8++;
        for (z8 = o13.layoutNodes[M9]; -1 === N8.indexOf(z8.id); )
          z8 = o13.layoutNodes[o13.idToIndex[z8.parentId]], I8++;
        D7 *= I8 * n13.nestingFactor;
      }
      S8.idealLength = D7, S8.elasticity = P10, o13.layoutEdges.push(S8);
    }
    return o13;
  };
  var Co = function(e22, t17, n13) {
    var r10 = So(e22, t17, 0, n13);
    return 2 > r10.count ? 0 : r10.graph;
  };
  var So = function e13(t17, n13, r10, a10) {
    var i11 = a10.graphSet[r10];
    if (-1 < i11.indexOf(t17) && -1 < i11.indexOf(n13))
      return { count: 2, graph: r10 };
    for (var o13 = 0, s11 = 0; s11 < i11.length; s11++) {
      var l11 = i11[s11], u10 = a10.idToIndex[l11], c10 = a10.layoutNodes[u10].children;
      if (0 !== c10.length) {
        var d12 = e13(t17, n13, a10.indexToGraph[a10.idToIndex[c10[0]]], a10);
        if (0 !== d12.count) {
          if (1 !== d12.count)
            return d12;
          if (2 === ++o13)
            break;
        }
      }
    }
    return { count: o13, graph: r10 };
  };
  var Do = function(e22, t17) {
    for (var n13 = e22.clientWidth, r10 = e22.clientHeight, a10 = 0; a10 < e22.nodeSize; a10++) {
      var i11 = e22.layoutNodes[a10];
      0 !== i11.children.length || i11.isLocked || (i11.positionX = Math.random() * n13, i11.positionY = Math.random() * r10);
    }
  };
  var Po = function(e22, t17, n13) {
    var r10 = e22.boundingBox, a10 = { x1: 1 / 0, x2: -1 / 0, y1: 1 / 0, y2: -1 / 0 };
    return t17.boundingBox && (n13.forEach(function(t18) {
      var n14 = e22.layoutNodes[e22.idToIndex[t18.data("id")]];
      a10.x1 = Math.min(a10.x1, n14.positionX), a10.x2 = Math.max(a10.x2, n14.positionX), a10.y1 = Math.min(a10.y1, n14.positionY), a10.y2 = Math.max(a10.y2, n14.positionY);
    }), a10.w = a10.x2 - a10.x1, a10.h = a10.y2 - a10.y1), function(n14, i11) {
      var o13 = e22.layoutNodes[e22.idToIndex[n14.data("id")]];
      if (t17.boundingBox) {
        var s11 = (o13.positionX - a10.x1) / a10.w, l11 = (o13.positionY - a10.y1) / a10.h;
        return { x: r10.x1 + s11 * r10.w, y: r10.y1 + l11 * r10.h };
      }
      return { x: o13.positionX, y: o13.positionY };
    };
  };
  var To = function(e22, t17, n13) {
    var r10 = n13.layout, a10 = n13.eles.nodes(), i11 = Po(e22, n13, a10);
    a10.positions(i11), true !== e22.ready && (e22.ready = true, r10.one("layoutready", n13.ready), r10.emit({ type: "layoutready", layout: this }));
  };
  var Mo = function(e22, t17, n13) {
    Bo(e22, t17), Lo(e22), Ao(e22, t17), Oo(e22), Ro(e22);
  };
  var Bo = function(e22, t17) {
    for (var n13 = 0; n13 < e22.graphSet.length; n13++)
      for (var r10 = e22.graphSet[n13], a10 = r10.length, i11 = 0; i11 < a10; i11++)
        for (var o13 = e22.layoutNodes[e22.idToIndex[r10[i11]]], s11 = i11 + 1; s11 < a10; s11++) {
          var l11 = e22.layoutNodes[e22.idToIndex[r10[s11]]];
          No(o13, l11, e22, t17);
        }
  };
  var _o = function(e22) {
    return -e22 + 2 * e22 * Math.random();
  };
  var No = function(e22, t17, n13, r10) {
    if (e22.cmptId === t17.cmptId || n13.isCompound) {
      var a10 = t17.positionX - e22.positionX, i11 = t17.positionY - e22.positionY;
      0 === a10 && 0 === i11 && (a10 = _o(1), i11 = _o(1));
      var o13 = Io(e22, t17, a10, i11);
      if (o13 > 0)
        var s11 = (u10 = r10.nodeOverlap * o13) * a10 / (g9 = Math.sqrt(a10 * a10 + i11 * i11)), l11 = u10 * i11 / g9;
      else {
        var u10, c10 = zo(e22, a10, i11), d12 = zo(t17, -1 * a10, -1 * i11), h10 = d12.x - c10.x, p10 = d12.y - c10.y, f11 = h10 * h10 + p10 * p10, g9 = Math.sqrt(f11);
        s11 = (u10 = (e22.nodeRepulsion + t17.nodeRepulsion) / f11) * h10 / g9, l11 = u10 * p10 / g9;
      }
      e22.isLocked || (e22.offsetX -= s11, e22.offsetY -= l11), t17.isLocked || (t17.offsetX += s11, t17.offsetY += l11);
    }
  };
  var Io = function(e22, t17, n13, r10) {
    if (n13 > 0)
      var a10 = e22.maxX - t17.minX;
    else
      a10 = t17.maxX - e22.minX;
    if (r10 > 0)
      var i11 = e22.maxY - t17.minY;
    else
      i11 = t17.maxY - e22.minY;
    return a10 >= 0 && i11 >= 0 ? Math.sqrt(a10 * a10 + i11 * i11) : 0;
  };
  var zo = function(e22, t17, n13) {
    var r10 = e22.positionX, a10 = e22.positionY, i11 = e22.height || 1, o13 = e22.width || 1, s11 = n13 / t17, l11 = i11 / o13, u10 = {};
    return 0 === t17 && 0 < n13 || 0 === t17 && 0 > n13 ? (u10.x = r10, u10.y = a10 + i11 / 2, u10) : 0 < t17 && -1 * l11 <= s11 && s11 <= l11 ? (u10.x = r10 + o13 / 2, u10.y = a10 + o13 * n13 / 2 / t17, u10) : 0 > t17 && -1 * l11 <= s11 && s11 <= l11 ? (u10.x = r10 - o13 / 2, u10.y = a10 - o13 * n13 / 2 / t17, u10) : 0 < n13 && (s11 <= -1 * l11 || s11 >= l11) ? (u10.x = r10 + i11 * t17 / 2 / n13, u10.y = a10 + i11 / 2, u10) : 0 > n13 && (s11 <= -1 * l11 || s11 >= l11) ? (u10.x = r10 - i11 * t17 / 2 / n13, u10.y = a10 - i11 / 2, u10) : u10;
  };
  var Lo = function(e22, t17) {
    for (var n13 = 0; n13 < e22.edgeSize; n13++) {
      var r10 = e22.layoutEdges[n13], a10 = e22.idToIndex[r10.sourceId], i11 = e22.layoutNodes[a10], o13 = e22.idToIndex[r10.targetId], s11 = e22.layoutNodes[o13], l11 = s11.positionX - i11.positionX, u10 = s11.positionY - i11.positionY;
      if (0 !== l11 || 0 !== u10) {
        var c10 = zo(i11, l11, u10), d12 = zo(s11, -1 * l11, -1 * u10), h10 = d12.x - c10.x, p10 = d12.y - c10.y, f11 = Math.sqrt(h10 * h10 + p10 * p10), g9 = Math.pow(r10.idealLength - f11, 2) / r10.elasticity;
        if (0 !== f11)
          var v12 = g9 * h10 / f11, y10 = g9 * p10 / f11;
        else
          v12 = 0, y10 = 0;
        i11.isLocked || (i11.offsetX += v12, i11.offsetY += y10), s11.isLocked || (s11.offsetX -= v12, s11.offsetY -= y10);
      }
    }
  };
  var Ao = function(e22, t17) {
    if (0 !== t17.gravity)
      for (var n13 = 0; n13 < e22.graphSet.length; n13++) {
        var r10 = e22.graphSet[n13], a10 = r10.length;
        if (0 === n13)
          var i11 = e22.clientHeight / 2, o13 = e22.clientWidth / 2;
        else {
          var s11 = e22.layoutNodes[e22.idToIndex[r10[0]]], l11 = e22.layoutNodes[e22.idToIndex[s11.parentId]];
          i11 = l11.positionX, o13 = l11.positionY;
        }
        for (var u10 = 0; u10 < a10; u10++) {
          var c10 = e22.layoutNodes[e22.idToIndex[r10[u10]]];
          if (!c10.isLocked) {
            var d12 = i11 - c10.positionX, h10 = o13 - c10.positionY, p10 = Math.sqrt(d12 * d12 + h10 * h10);
            if (p10 > 1) {
              var f11 = t17.gravity * d12 / p10, g9 = t17.gravity * h10 / p10;
              c10.offsetX += f11, c10.offsetY += g9;
            }
          }
        }
      }
  };
  var Oo = function(e22, t17) {
    var n13 = [], r10 = 0, a10 = -1;
    for (n13.push.apply(n13, e22.graphSet[0]), a10 += e22.graphSet[0].length; r10 <= a10; ) {
      var i11 = n13[r10++], o13 = e22.idToIndex[i11], s11 = e22.layoutNodes[o13], l11 = s11.children;
      if (0 < l11.length && !s11.isLocked) {
        for (var u10 = s11.offsetX, c10 = s11.offsetY, d12 = 0; d12 < l11.length; d12++) {
          var h10 = e22.layoutNodes[e22.idToIndex[l11[d12]]];
          h10.offsetX += u10, h10.offsetY += c10, n13[++a10] = l11[d12];
        }
        s11.offsetX = 0, s11.offsetY = 0;
      }
    }
  };
  var Ro = function(e22, t17) {
    for (var n13 = 0; n13 < e22.nodeSize; n13++) {
      0 < (a10 = e22.layoutNodes[n13]).children.length && (a10.maxX = void 0, a10.minX = void 0, a10.maxY = void 0, a10.minY = void 0);
    }
    for (n13 = 0; n13 < e22.nodeSize; n13++) {
      if (!(0 < (a10 = e22.layoutNodes[n13]).children.length || a10.isLocked)) {
        var r10 = Vo(a10.offsetX, a10.offsetY, e22.temperature);
        a10.positionX += r10.x, a10.positionY += r10.y, a10.offsetX = 0, a10.offsetY = 0, a10.minX = a10.positionX - a10.width, a10.maxX = a10.positionX + a10.width, a10.minY = a10.positionY - a10.height, a10.maxY = a10.positionY + a10.height, Fo(a10, e22);
      }
    }
    for (n13 = 0; n13 < e22.nodeSize; n13++) {
      var a10;
      0 < (a10 = e22.layoutNodes[n13]).children.length && !a10.isLocked && (a10.positionX = (a10.maxX + a10.minX) / 2, a10.positionY = (a10.maxY + a10.minY) / 2, a10.width = a10.maxX - a10.minX, a10.height = a10.maxY - a10.minY);
    }
  };
  var Vo = function(e22, t17, n13) {
    var r10 = Math.sqrt(e22 * e22 + t17 * t17);
    if (r10 > n13)
      var a10 = { x: n13 * e22 / r10, y: n13 * t17 / r10 };
    else
      a10 = { x: e22, y: t17 };
    return a10;
  };
  var Fo = function e14(t17, n13) {
    var r10 = t17.parentId;
    if (null != r10) {
      var a10 = n13.layoutNodes[n13.idToIndex[r10]], i11 = false;
      return (null == a10.maxX || t17.maxX + a10.padRight > a10.maxX) && (a10.maxX = t17.maxX + a10.padRight, i11 = true), (null == a10.minX || t17.minX - a10.padLeft < a10.minX) && (a10.minX = t17.minX - a10.padLeft, i11 = true), (null == a10.maxY || t17.maxY + a10.padBottom > a10.maxY) && (a10.maxY = t17.maxY + a10.padBottom, i11 = true), (null == a10.minY || t17.minY - a10.padTop < a10.minY) && (a10.minY = t17.minY - a10.padTop, i11 = true), i11 ? e14(a10, n13) : void 0;
    }
  };
  var qo = function(e22, t17) {
    for (var n13 = e22.layoutNodes, r10 = [], a10 = 0; a10 < n13.length; a10++) {
      var i11 = n13[a10], o13 = i11.cmptId;
      (r10[o13] = r10[o13] || []).push(i11);
    }
    var s11 = 0;
    for (a10 = 0; a10 < r10.length; a10++) {
      if (g9 = r10[a10]) {
        g9.x1 = 1 / 0, g9.x2 = -1 / 0, g9.y1 = 1 / 0, g9.y2 = -1 / 0;
        for (var l11 = 0; l11 < g9.length; l11++) {
          var u10 = g9[l11];
          g9.x1 = Math.min(g9.x1, u10.positionX - u10.width / 2), g9.x2 = Math.max(g9.x2, u10.positionX + u10.width / 2), g9.y1 = Math.min(g9.y1, u10.positionY - u10.height / 2), g9.y2 = Math.max(g9.y2, u10.positionY + u10.height / 2);
        }
        g9.w = g9.x2 - g9.x1, g9.h = g9.y2 - g9.y1, s11 += g9.w * g9.h;
      }
    }
    r10.sort(function(e23, t18) {
      return t18.w * t18.h - e23.w * e23.h;
    });
    var c10 = 0, d12 = 0, h10 = 0, p10 = 0, f11 = Math.sqrt(s11) * e22.clientWidth / e22.clientHeight;
    for (a10 = 0; a10 < r10.length; a10++) {
      var g9;
      if (g9 = r10[a10]) {
        for (l11 = 0; l11 < g9.length; l11++) {
          (u10 = g9[l11]).isLocked || (u10.positionX += c10 - g9.x1, u10.positionY += d12 - g9.y1);
        }
        c10 += g9.w + t17.componentSpacing, h10 += g9.w + t17.componentSpacing, p10 = Math.max(p10, g9.h), h10 > f11 && (d12 += p10 + t17.componentSpacing, c10 = 0, h10 = 0, p10 = 0);
      }
    }
  };
  var jo = { fit: true, padding: 30, boundingBox: void 0, avoidOverlap: true, avoidOverlapPadding: 10, nodeDimensionsIncludeLabels: false, spacingFactor: void 0, condense: false, rows: void 0, cols: void 0, position: function(e22) {
  }, sort: void 0, animate: false, animationDuration: 500, animationEasing: void 0, animateFilter: function(e22, t17) {
    return true;
  }, ready: void 0, stop: void 0, transform: function(e22, t17) {
    return t17;
  } };
  function Yo(e22) {
    this.options = J4({}, jo, e22);
  }
  Yo.prototype.run = function() {
    var e22 = this.options, t17 = e22, n13 = e22.cy, r10 = t17.eles, a10 = r10.nodes().not(":parent");
    t17.sort && (a10 = a10.sort(t17.sort));
    var i11 = vt4(t17.boundingBox ? t17.boundingBox : { x1: 0, y1: 0, w: n13.width(), h: n13.height() });
    if (0 === i11.h || 0 === i11.w)
      r10.nodes().layoutPositions(this, t17, function(e23) {
        return { x: i11.x1, y: i11.y1 };
      });
    else {
      var o13 = a10.size(), s11 = Math.sqrt(o13 * i11.h / i11.w), l11 = Math.round(s11), u10 = Math.round(i11.w / i11.h * s11), c10 = function(e23) {
        if (null == e23)
          return Math.min(l11, u10);
        Math.min(l11, u10) == l11 ? l11 = e23 : u10 = e23;
      }, d12 = function(e23) {
        if (null == e23)
          return Math.max(l11, u10);
        Math.max(l11, u10) == l11 ? l11 = e23 : u10 = e23;
      }, h10 = t17.rows, p10 = null != t17.cols ? t17.cols : t17.columns;
      if (null != h10 && null != p10)
        l11 = h10, u10 = p10;
      else if (null != h10 && null == p10)
        l11 = h10, u10 = Math.ceil(o13 / l11);
      else if (null == h10 && null != p10)
        u10 = p10, l11 = Math.ceil(o13 / u10);
      else if (u10 * l11 > o13) {
        var f11 = c10(), g9 = d12();
        (f11 - 1) * g9 >= o13 ? c10(f11 - 1) : (g9 - 1) * f11 >= o13 && d12(g9 - 1);
      } else
        for (; u10 * l11 < o13; ) {
          var v12 = c10(), y10 = d12();
          (y10 + 1) * v12 >= o13 ? d12(y10 + 1) : c10(v12 + 1);
        }
      var m12 = i11.w / u10, b11 = i11.h / l11;
      if (t17.condense && (m12 = 0, b11 = 0), t17.avoidOverlap)
        for (var x11 = 0; x11 < a10.length; x11++) {
          var w10 = a10[x11], E10 = w10._private.position;
          null != E10.x && null != E10.y || (E10.x = 0, E10.y = 0);
          var k10 = w10.layoutDimensions(t17), C9 = t17.avoidOverlapPadding, S8 = k10.w + C9, D7 = k10.h + C9;
          m12 = Math.max(m12, S8), b11 = Math.max(b11, D7);
        }
      for (var P10 = {}, T9 = function(e23, t18) {
        return !!P10["c-" + e23 + "-" + t18];
      }, M9 = function(e23, t18) {
        P10["c-" + e23 + "-" + t18] = true;
      }, B8 = 0, _7 = 0, N8 = function() {
        ++_7 >= u10 && (_7 = 0, B8++);
      }, I8 = {}, z8 = 0; z8 < a10.length; z8++) {
        var L10 = a10[z8], A10 = t17.position(L10);
        if (A10 && (void 0 !== A10.row || void 0 !== A10.col)) {
          var O9 = { row: A10.row, col: A10.col };
          if (void 0 === O9.col)
            for (O9.col = 0; T9(O9.row, O9.col); )
              O9.col++;
          else if (void 0 === O9.row)
            for (O9.row = 0; T9(O9.row, O9.col); )
              O9.row++;
          I8[L10.id()] = O9, M9(O9.row, O9.col);
        }
      }
      a10.layoutPositions(this, t17, function(e23, t18) {
        var n14, r11;
        if (e23.locked() || e23.isParent())
          return false;
        var a11 = I8[e23.id()];
        if (a11)
          n14 = a11.col * m12 + m12 / 2 + i11.x1, r11 = a11.row * b11 + b11 / 2 + i11.y1;
        else {
          for (; T9(B8, _7); )
            N8();
          n14 = _7 * m12 + m12 / 2 + i11.x1, r11 = B8 * b11 + b11 / 2 + i11.y1, M9(B8, _7), N8();
        }
        return { x: n14, y: r11 };
      });
    }
    return this;
  };
  var Xo = { ready: function() {
  }, stop: function() {
  } };
  function Wo(e22) {
    this.options = J4({}, Xo, e22);
  }
  Wo.prototype.run = function() {
    var e22 = this.options, t17 = e22.eles, n13 = this;
    return e22.cy, n13.emit("layoutstart"), t17.nodes().positions(function() {
      return { x: 0, y: 0 };
    }), n13.one("layoutready", e22.ready), n13.emit("layoutready"), n13.one("layoutstop", e22.stop), n13.emit("layoutstop"), this;
  }, Wo.prototype.stop = function() {
    return this;
  };
  var Ho = { positions: void 0, zoom: void 0, pan: void 0, fit: true, padding: 30, animate: false, animationDuration: 500, animationEasing: void 0, animateFilter: function(e22, t17) {
    return true;
  }, ready: void 0, stop: void 0, transform: function(e22, t17) {
    return t17;
  } };
  function Ko(e22) {
    this.options = J4({}, Ho, e22);
  }
  Ko.prototype.run = function() {
    var e22 = this.options, t17 = e22.eles.nodes(), n13 = B4(e22.positions);
    return t17.layoutPositions(this, e22, function(t18, r10) {
      var a10 = function(t19) {
        if (null == e22.positions)
          return function(e23) {
            return { x: e23.x, y: e23.y };
          }(t19.position());
        if (n13)
          return e22.positions(t19);
        var r11 = e22.positions[t19._private.data.id];
        return null == r11 ? null : r11;
      }(t18);
      return !t18.locked() && null != a10 && a10;
    }), this;
  };
  var Go = { fit: true, padding: 30, boundingBox: void 0, animate: false, animationDuration: 500, animationEasing: void 0, animateFilter: function(e22, t17) {
    return true;
  }, ready: void 0, stop: void 0, transform: function(e22, t17) {
    return t17;
  } };
  function Uo(e22) {
    this.options = J4({}, Go, e22);
  }
  Uo.prototype.run = function() {
    var e22 = this.options, t17 = e22.cy, n13 = e22.eles, r10 = vt4(e22.boundingBox ? e22.boundingBox : { x1: 0, y1: 0, w: t17.width(), h: t17.height() });
    return n13.nodes().layoutPositions(this, e22, function(e23, t18) {
      return { x: r10.x1 + Math.round(Math.random() * r10.w), y: r10.y1 + Math.round(Math.random() * r10.h) };
    }), this;
  };
  var Zo = [{ name: "breadthfirst", impl: go }, { name: "circle", impl: yo }, { name: "concentric", impl: xo }, { name: "cose", impl: Eo }, { name: "grid", impl: Yo }, { name: "null", impl: Wo }, { name: "preset", impl: Ko }, { name: "random", impl: Uo }];
  function $o(e22) {
    this.options = e22, this.notifications = 0;
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
    var e22 = this.arrowShapes = {}, t17 = this, n13 = function(e23, t18, n14, r11, a11, i12, o14) {
      var s12 = a11.x - n14 / 2 - o14, l11 = a11.x + n14 / 2 + o14, u10 = a11.y - n14 / 2 - o14, c10 = a11.y + n14 / 2 + o14;
      return s12 <= e23 && e23 <= l11 && u10 <= t18 && t18 <= c10;
    }, r10 = function(e23, t18, n14, r11, a11) {
      var i12 = e23 * Math.cos(r11) - t18 * Math.sin(r11), o14 = (e23 * Math.sin(r11) + t18 * Math.cos(r11)) * n14;
      return { x: i12 * n14 + a11.x, y: o14 + a11.y };
    }, a10 = function(e23, t18, n14, a11) {
      for (var i12 = [], o14 = 0; o14 < e23.length; o14 += 2) {
        var s12 = e23[o14], l11 = e23[o14 + 1];
        i12.push(r10(s12, l11, t18, n14, a11));
      }
      return i12;
    }, i11 = function(e23) {
      for (var t18 = [], n14 = 0; n14 < e23.length; n14++) {
        var r11 = e23[n14];
        t18.push(r11.x, r11.y);
      }
      return t18;
    }, o13 = function(e23) {
      return e23.pstyle("width").pfValue * e23.pstyle("arrow-scale").pfValue * 2;
    }, s11 = function(r11, s12) {
      M6(s12) && (s12 = e22[s12]), e22[r11] = J4({ name: r11, points: [-0.15, -0.3, 0.15, -0.3, 0.15, 0.3, -0.15, 0.3], collide: function(e23, t18, n14, r12, o14, s13) {
        var l11 = i11(a10(this.points, n14 + 2 * s13, r12, o14));
        return Mt4(e23, t18, l11);
      }, roughCollide: n13, draw: function(e23, n14, r12, i12) {
        var o14 = a10(this.points, n14, r12, i12);
        t17.arrowShapeImpl("polygon")(e23, o14);
      }, spacing: function(e23) {
        return 0;
      }, gap: o13 }, s12);
    };
    s11("none", { collide: Ce, roughCollide: Ce, draw: De, spacing: Se, gap: Se }), s11("triangle", { points: [-0.15, -0.3, 0, 0, 0.15, -0.3] }), s11("arrow", "triangle"), s11("triangle-backcurve", { points: e22.triangle.points, controlPoint: [0, -0.15], roughCollide: n13, draw: function(e23, n14, i12, o14, s12) {
      var l11 = a10(this.points, n14, i12, o14), u10 = this.controlPoint, c10 = r10(u10[0], u10[1], n14, i12, o14);
      t17.arrowShapeImpl(this.name)(e23, l11, c10);
    }, gap: function(e23) {
      return 0.8 * o13(e23);
    } }), s11("triangle-tee", { points: [0, 0, 0.15, -0.3, -0.15, -0.3, 0, 0], pointsTee: [-0.15, -0.4, -0.15, -0.5, 0.15, -0.5, 0.15, -0.4], collide: function(e23, t18, n14, r11, o14, s12, l11) {
      var u10 = i11(a10(this.points, n14 + 2 * l11, r11, o14)), c10 = i11(a10(this.pointsTee, n14 + 2 * l11, r11, o14));
      return Mt4(e23, t18, u10) || Mt4(e23, t18, c10);
    }, draw: function(e23, n14, r11, i12, o14) {
      var s12 = a10(this.points, n14, r11, i12), l11 = a10(this.pointsTee, n14, r11, i12);
      t17.arrowShapeImpl(this.name)(e23, s12, l11);
    } }), s11("circle-triangle", { radius: 0.15, pointsTr: [0, -0.15, 0.15, -0.45, -0.15, -0.45, 0, -0.15], collide: function(e23, t18, n14, r11, o14, s12, l11) {
      var u10 = o14, c10 = Math.pow(u10.x - e23, 2) + Math.pow(u10.y - t18, 2) <= Math.pow((n14 + 2 * l11) * this.radius, 2), d12 = i11(a10(this.points, n14 + 2 * l11, r11, o14));
      return Mt4(e23, t18, d12) || c10;
    }, draw: function(e23, n14, r11, i12, o14) {
      var s12 = a10(this.pointsTr, n14, r11, i12);
      t17.arrowShapeImpl(this.name)(e23, s12, i12.x, i12.y, this.radius * n14);
    }, spacing: function(e23) {
      return t17.getArrowWidth(e23.pstyle("width").pfValue, e23.pstyle("arrow-scale").value) * this.radius;
    } }), s11("triangle-cross", { points: [0, 0, 0.15, -0.3, -0.15, -0.3, 0, 0], baseCrossLinePts: [-0.15, -0.4, -0.15, -0.4, 0.15, -0.4, 0.15, -0.4], crossLinePts: function(e23, t18) {
      var n14 = this.baseCrossLinePts.slice(), r11 = t18 / e23;
      return n14[3] = n14[3] - r11, n14[5] = n14[5] - r11, n14;
    }, collide: function(e23, t18, n14, r11, o14, s12, l11) {
      var u10 = i11(a10(this.points, n14 + 2 * l11, r11, o14)), c10 = i11(a10(this.crossLinePts(n14, s12), n14 + 2 * l11, r11, o14));
      return Mt4(e23, t18, u10) || Mt4(e23, t18, c10);
    }, draw: function(e23, n14, r11, i12, o14) {
      var s12 = a10(this.points, n14, r11, i12), l11 = a10(this.crossLinePts(n14, o14), n14, r11, i12);
      t17.arrowShapeImpl(this.name)(e23, s12, l11);
    } }), s11("vee", { points: [-0.15, -0.3, 0, 0, 0.15, -0.3, 0, -0.15], gap: function(e23) {
      return 0.525 * o13(e23);
    } }), s11("circle", { radius: 0.15, collide: function(e23, t18, n14, r11, a11, i12, o14) {
      var s12 = a11;
      return Math.pow(s12.x - e23, 2) + Math.pow(s12.y - t18, 2) <= Math.pow((n14 + 2 * o14) * this.radius, 2);
    }, draw: function(e23, n14, r11, a11, i12) {
      t17.arrowShapeImpl(this.name)(e23, a11.x, a11.y, this.radius * n14);
    }, spacing: function(e23) {
      return t17.getArrowWidth(e23.pstyle("width").pfValue, e23.pstyle("arrow-scale").value) * this.radius;
    } }), s11("tee", { points: [-0.15, 0, -0.15, -0.1, 0.15, -0.1, 0.15, 0], spacing: function(e23) {
      return 1;
    }, gap: function(e23) {
      return 1;
    } }), s11("square", { points: [-0.15, 0, 0.15, 0, 0.15, -0.3, -0.15, -0.3] }), s11("diamond", { points: [-0.15, -0.15, 0, -0.3, 0.15, -0.15, 0, 0], gap: function(e23) {
      return e23.pstyle("width").pfValue * e23.pstyle("arrow-scale").value;
    } }), s11("chevron", { points: [0, 0, -0.15, -0.15, -0.1, -0.2, 0, -0.1, 0.1, -0.2, 0.15, -0.15], gap: function(e23) {
      return 0.95 * e23.pstyle("width").pfValue * e23.pstyle("arrow-scale").value;
    } });
  } };
  var ts = { projectIntoViewport: function(e22, t17) {
    var n13 = this.cy, r10 = this.findContainerClientCoords(), a10 = r10[0], i11 = r10[1], o13 = r10[4], s11 = n13.pan(), l11 = n13.zoom();
    return [((e22 - a10) / o13 - s11.x) / l11, ((t17 - i11) / o13 - s11.y) / l11];
  }, findContainerClientCoords: function() {
    if (this.containerBB)
      return this.containerBB;
    var e22 = this.container, t17 = e22.getBoundingClientRect(), n13 = this.cy.window().getComputedStyle(e22), r10 = function(e23) {
      return parseFloat(n13.getPropertyValue(e23));
    }, a10 = r10("padding-left"), i11 = r10("padding-right"), o13 = r10("padding-top"), s11 = r10("padding-bottom"), l11 = r10("border-left-width"), u10 = r10("border-right-width"), c10 = r10("border-top-width"), d12 = (r10("border-bottom-width"), e22.clientWidth), h10 = e22.clientHeight, p10 = a10 + i11, f11 = o13 + s11, g9 = l11 + u10, v12 = t17.width / (d12 + g9), y10 = d12 - p10, m12 = h10 - f11, b11 = t17.left + a10 + l11, x11 = t17.top + o13 + c10;
    return this.containerBB = [b11, x11, y10, m12, v12];
  }, invalidateContainerClientCoordsCache: function() {
    this.containerBB = null;
  }, findNearestElement: function(e22, t17, n13, r10) {
    return this.findNearestElements(e22, t17, n13, r10)[0];
  }, findNearestElements: function(e22, t17, n13, r10) {
    var a10, i11, o13 = this, s11 = this, l11 = s11.getCachedZSortedEles(), u10 = [], c10 = s11.cy.zoom(), d12 = s11.cy.hasCompoundNodes(), h10 = (r10 ? 24 : 8) / c10, p10 = (r10 ? 8 : 2) / c10, f11 = (r10 ? 8 : 2) / c10, g9 = 1 / 0;
    function v12(e23, t18) {
      if (e23.isNode()) {
        if (i11)
          return;
        i11 = e23, u10.push(e23);
      }
      if (e23.isEdge() && (null == t18 || t18 < g9))
        if (a10) {
          if (a10.pstyle("z-compound-depth").value === e23.pstyle("z-compound-depth").value && a10.pstyle("z-compound-depth").value === e23.pstyle("z-compound-depth").value) {
            for (var n14 = 0; n14 < u10.length; n14++)
              if (u10[n14].isEdge()) {
                u10[n14] = e23, a10 = e23, g9 = null != t18 ? t18 : g9;
                break;
              }
          }
        } else
          u10.push(e23), a10 = e23, g9 = null != t18 ? t18 : g9;
    }
    function y10(n14) {
      var r11 = n14.outerWidth() + 2 * p10, a11 = n14.outerHeight() + 2 * p10, i12 = r11 / 2, l12 = a11 / 2, u11 = n14.position();
      if (u11.x - i12 <= e22 && e22 <= u11.x + i12 && u11.y - l12 <= t17 && t17 <= u11.y + l12 && s11.nodeShapes[o13.getNodeShape(n14)].checkPoint(e22, t17, 0, r11, a11, u11.x, u11.y))
        return v12(n14, 0), true;
    }
    function m12(n14) {
      var r11, a11 = n14._private, i12 = a11.rscratch, l12 = n14.pstyle("width").pfValue, c11 = n14.pstyle("arrow-scale").value, p11 = l12 / 2 + h10, f12 = p11 * p11, g10 = 2 * p11, m13 = a11.source, b12 = a11.target;
      if ("segments" === i12.edgeType || "straight" === i12.edgeType || "haystack" === i12.edgeType) {
        for (var x12 = i12.allpts, w11 = 0; w11 + 3 < x12.length; w11 += 2)
          if (St4(e22, t17, x12[w11], x12[w11 + 1], x12[w11 + 2], x12[w11 + 3], g10) && f12 > (r11 = Tt4(e22, t17, x12[w11], x12[w11 + 1], x12[w11 + 2], x12[w11 + 3])))
            return v12(n14, r11), true;
      } else if ("bezier" === i12.edgeType || "multibezier" === i12.edgeType || "self" === i12.edgeType || "compound" === i12.edgeType) {
        for (x12 = i12.allpts, w11 = 0; w11 + 5 < i12.allpts.length; w11 += 4)
          if (Dt4(e22, t17, x12[w11], x12[w11 + 1], x12[w11 + 2], x12[w11 + 3], x12[w11 + 4], x12[w11 + 5], g10) && f12 > (r11 = Pt4(e22, t17, x12[w11], x12[w11 + 1], x12[w11 + 2], x12[w11 + 3], x12[w11 + 4], x12[w11 + 5])))
            return v12(n14, r11), true;
      }
      m13 = m13 || a11.source, b12 = b12 || a11.target;
      var E11 = o13.getArrowWidth(l12, c11), k10 = [{ name: "source", x: i12.arrowStartX, y: i12.arrowStartY, angle: i12.srcArrowAngle }, { name: "target", x: i12.arrowEndX, y: i12.arrowEndY, angle: i12.tgtArrowAngle }, { name: "mid-source", x: i12.midX, y: i12.midY, angle: i12.midsrcArrowAngle }, { name: "mid-target", x: i12.midX, y: i12.midY, angle: i12.midtgtArrowAngle }];
      for (w11 = 0; w11 < k10.length; w11++) {
        var C9 = k10[w11], S8 = s11.arrowShapes[n14.pstyle(C9.name + "-arrow-shape").value], D7 = n14.pstyle("width").pfValue;
        if (S8.roughCollide(e22, t17, E11, C9.angle, { x: C9.x, y: C9.y }, D7, h10) && S8.collide(e22, t17, E11, C9.angle, { x: C9.x, y: C9.y }, D7, h10))
          return v12(n14), true;
      }
      d12 && u10.length > 0 && (y10(m13), y10(b12));
    }
    function b11(e23, t18, n14) {
      return Oe(e23, t18, n14);
    }
    function x11(n14, r11) {
      var a11, i12 = n14._private, o14 = f11;
      a11 = r11 ? r11 + "-" : "", n14.boundingBox();
      var s12 = i12.labelBounds[r11 || "main"], l12 = n14.pstyle(a11 + "label").value;
      if ("yes" === n14.pstyle("text-events").strValue && l12) {
        var u11 = b11(i12.rscratch, "labelX", r11), c11 = b11(i12.rscratch, "labelY", r11), d13 = b11(i12.rscratch, "labelAngle", r11), h11 = n14.pstyle(a11 + "text-margin-x").pfValue, p11 = n14.pstyle(a11 + "text-margin-y").pfValue, g10 = s12.x1 - o14 - h11, y11 = s12.x2 + o14 - h11, m13 = s12.y1 - o14 - p11, x12 = s12.y2 + o14 - p11;
        if (d13) {
          var w11 = Math.cos(d13), E11 = Math.sin(d13), k10 = function(e23, t18) {
            return { x: (e23 -= u11) * w11 - (t18 -= c11) * E11 + u11, y: e23 * E11 + t18 * w11 + c11 };
          }, C9 = k10(g10, m13), S8 = k10(g10, x12), D7 = k10(y11, m13), P10 = k10(y11, x12), T9 = [C9.x + h11, C9.y + p11, D7.x + h11, D7.y + p11, P10.x + h11, P10.y + p11, S8.x + h11, S8.y + p11];
          if (Mt4(e22, t17, T9))
            return v12(n14), true;
        } else if (Et4(s12, e22, t17))
          return v12(n14), true;
      }
    }
    n13 && (l11 = l11.interactive);
    for (var w10 = l11.length - 1; w10 >= 0; w10--) {
      var E10 = l11[w10];
      E10.isNode() ? y10(E10) || x11(E10) : m12(E10) || x11(E10) || x11(E10, "source") || x11(E10, "target");
    }
    return u10;
  }, getAllInBox: function(e22, t17, n13, r10) {
    for (var a10, i11, o13 = this.getCachedZSortedEles().interactive, s11 = [], l11 = Math.min(e22, n13), u10 = Math.max(e22, n13), c10 = Math.min(t17, r10), d12 = Math.max(t17, r10), h10 = vt4({ x1: e22 = l11, y1: t17 = c10, x2: n13 = u10, y2: r10 = d12 }), p10 = 0; p10 < o13.length; p10++) {
      var f11 = o13[p10];
      if (f11.isNode()) {
        var g9 = f11, v12 = g9.boundingBox({ includeNodes: true, includeEdges: false, includeLabels: false });
        wt4(h10, v12) && !kt4(v12, h10) && s11.push(g9);
      } else {
        var y10 = f11, m12 = y10._private, b11 = m12.rscratch;
        if (null != b11.startX && null != b11.startY && !Et4(h10, b11.startX, b11.startY))
          continue;
        if (null != b11.endX && null != b11.endY && !Et4(h10, b11.endX, b11.endY))
          continue;
        if ("bezier" === b11.edgeType || "multibezier" === b11.edgeType || "self" === b11.edgeType || "compound" === b11.edgeType || "segments" === b11.edgeType || "haystack" === b11.edgeType) {
          for (var x11 = m12.rstyle.bezierPts || m12.rstyle.linePts || m12.rstyle.haystackPts, w10 = true, E10 = 0; E10 < x11.length; E10++)
            if (a10 = h10, i11 = x11[E10], !Et4(a10, i11.x, i11.y)) {
              w10 = false;
              break;
            }
          w10 && s11.push(y10);
        } else
          "haystack" !== b11.edgeType && "straight" !== b11.edgeType || s11.push(y10);
      }
    }
    return s11;
  } };
  var ns = { calculateArrowAngles: function(e22) {
    var t17, n13, r10, a10, i11, o13, s11 = e22._private.rscratch, l11 = "haystack" === s11.edgeType, u10 = "bezier" === s11.edgeType, c10 = "multibezier" === s11.edgeType, d12 = "segments" === s11.edgeType, h10 = "compound" === s11.edgeType, p10 = "self" === s11.edgeType;
    if (l11 ? (r10 = s11.haystackPts[0], a10 = s11.haystackPts[1], i11 = s11.haystackPts[2], o13 = s11.haystackPts[3]) : (r10 = s11.arrowStartX, a10 = s11.arrowStartY, i11 = s11.arrowEndX, o13 = s11.arrowEndY), g9 = s11.midX, v12 = s11.midY, d12)
      t17 = r10 - s11.segpts[0], n13 = a10 - s11.segpts[1];
    else if (c10 || h10 || p10 || u10) {
      var f11 = s11.allpts;
      t17 = r10 - pt4(f11[0], f11[2], f11[4], 0.1), n13 = a10 - pt4(f11[1], f11[3], f11[5], 0.1);
    } else
      t17 = r10 - g9, n13 = a10 - v12;
    s11.srcArrowAngle = st4(t17, n13);
    var g9 = s11.midX, v12 = s11.midY;
    if (l11 && (g9 = (r10 + i11) / 2, v12 = (a10 + o13) / 2), t17 = i11 - r10, n13 = o13 - a10, d12)
      if ((f11 = s11.allpts).length / 2 % 2 == 0) {
        var y10 = (m12 = f11.length / 2) - 2;
        t17 = f11[m12] - f11[y10], n13 = f11[m12 + 1] - f11[y10 + 1];
      } else {
        y10 = (m12 = f11.length / 2 - 1) - 2;
        var m12, b11 = m12 + 2;
        t17 = f11[m12] - f11[y10], n13 = f11[m12 + 1] - f11[y10 + 1];
      }
    else if (c10 || h10 || p10) {
      var x11, w10, E10, k10, f11 = s11.allpts;
      if (s11.ctrlpts.length / 2 % 2 == 0) {
        var C9 = (S8 = (D7 = f11.length / 2 - 1) + 2) + 2;
        x11 = pt4(f11[D7], f11[S8], f11[C9], 0), w10 = pt4(f11[D7 + 1], f11[S8 + 1], f11[C9 + 1], 0), E10 = pt4(f11[D7], f11[S8], f11[C9], 1e-4), k10 = pt4(f11[D7 + 1], f11[S8 + 1], f11[C9 + 1], 1e-4);
      } else {
        var S8, D7;
        C9 = (S8 = f11.length / 2 - 1) + 2;
        x11 = pt4(f11[D7 = S8 - 2], f11[S8], f11[C9], 0.4999), w10 = pt4(f11[D7 + 1], f11[S8 + 1], f11[C9 + 1], 0.4999), E10 = pt4(f11[D7], f11[S8], f11[C9], 0.5), k10 = pt4(f11[D7 + 1], f11[S8 + 1], f11[C9 + 1], 0.5);
      }
      t17 = E10 - x11, n13 = k10 - w10;
    }
    (s11.midtgtArrowAngle = st4(t17, n13), s11.midDispX = t17, s11.midDispY = n13, t17 *= -1, n13 *= -1, d12) && ((f11 = s11.allpts).length / 2 % 2 == 0 || (t17 = -(f11[b11 = (m12 = f11.length / 2 - 1) + 2] - f11[m12]), n13 = -(f11[b11 + 1] - f11[m12 + 1])));
    if (s11.midsrcArrowAngle = st4(t17, n13), d12)
      t17 = i11 - s11.segpts[s11.segpts.length - 2], n13 = o13 - s11.segpts[s11.segpts.length - 1];
    else if (c10 || h10 || p10 || u10) {
      var P10 = (f11 = s11.allpts).length;
      t17 = i11 - pt4(f11[P10 - 6], f11[P10 - 4], f11[P10 - 2], 0.9), n13 = o13 - pt4(f11[P10 - 5], f11[P10 - 3], f11[P10 - 1], 0.9);
    } else
      t17 = i11 - g9, n13 = o13 - v12;
    s11.tgtArrowAngle = st4(t17, n13);
  } };
  ns.getArrowWidth = ns.getArrowHeight = function(e22, t17) {
    var n13 = this.arrowWidthCache = this.arrowWidthCache || {}, r10 = n13[e22 + ", " + t17];
    return r10 || (r10 = Math.max(Math.pow(13.37 * e22, 0.9), 29) * t17, n13[e22 + ", " + t17] = r10, r10);
  };
  var rs = {};
  function as(e22) {
    var t17 = [];
    if (null != e22) {
      for (var n13 = 0; n13 < e22.length; n13 += 2) {
        var r10 = e22[n13], a10 = e22[n13 + 1];
        t17.push({ x: r10, y: a10 });
      }
      return t17;
    }
  }
  rs.findHaystackPoints = function(e22) {
    for (var t17 = 0; t17 < e22.length; t17++) {
      var n13 = e22[t17], r10 = n13._private, a10 = r10.rscratch;
      if (!a10.haystack) {
        var i11 = 2 * Math.random() * Math.PI;
        a10.source = { x: Math.cos(i11), y: Math.sin(i11) }, i11 = 2 * Math.random() * Math.PI, a10.target = { x: Math.cos(i11), y: Math.sin(i11) };
      }
      var o13 = r10.source, s11 = r10.target, l11 = o13.position(), u10 = s11.position(), c10 = o13.width(), d12 = s11.width(), h10 = o13.height(), p10 = s11.height(), f11 = n13.pstyle("haystack-radius").value / 2;
      a10.haystackPts = a10.allpts = [a10.source.x * c10 * f11 + l11.x, a10.source.y * h10 * f11 + l11.y, a10.target.x * d12 * f11 + u10.x, a10.target.y * p10 * f11 + u10.y], a10.midX = (a10.allpts[0] + a10.allpts[2]) / 2, a10.midY = (a10.allpts[1] + a10.allpts[3]) / 2, a10.edgeType = "haystack", a10.haystack = true, this.storeEdgeProjections(n13), this.calculateArrowAngles(n13), this.recalculateEdgeLabelProjections(n13), this.calculateLabelAngles(n13);
    }
  }, rs.findSegmentsPoints = function(e22, t17) {
    var n13 = e22._private.rscratch, r10 = t17.posPts, a10 = t17.intersectionPts, i11 = t17.vectorNormInverse, o13 = e22.pstyle("edge-distances").value, s11 = e22.pstyle("segment-weights"), l11 = e22.pstyle("segment-distances"), u10 = Math.min(s11.pfValue.length, l11.pfValue.length);
    n13.edgeType = "segments", n13.segpts = [];
    for (var c10 = 0; c10 < u10; c10++) {
      var d12 = s11.pfValue[c10], h10 = l11.pfValue[c10], p10 = 1 - d12, f11 = d12, g9 = "node-position" === o13 ? r10 : a10, v12 = { x: g9.x1 * p10 + g9.x2 * f11, y: g9.y1 * p10 + g9.y2 * f11 };
      n13.segpts.push(v12.x + i11.x * h10, v12.y + i11.y * h10);
    }
  }, rs.findLoopPoints = function(e22, t17, n13, r10) {
    var a10 = e22._private.rscratch, i11 = t17.dirCounts, o13 = t17.srcPos, s11 = e22.pstyle("control-point-distances"), l11 = s11 ? s11.pfValue[0] : void 0, u10 = e22.pstyle("loop-direction").pfValue, c10 = e22.pstyle("loop-sweep").pfValue, d12 = e22.pstyle("control-point-step-size").pfValue;
    a10.edgeType = "self";
    var h10 = n13, p10 = d12;
    r10 && (h10 = 0, p10 = l11);
    var f11 = u10 - Math.PI / 2, g9 = f11 - c10 / 2, v12 = f11 + c10 / 2, y10 = String(u10 + "_" + c10);
    h10 = void 0 === i11[y10] ? i11[y10] = 0 : ++i11[y10], a10.ctrlpts = [o13.x + 1.4 * Math.cos(g9) * p10 * (h10 / 3 + 1), o13.y + 1.4 * Math.sin(g9) * p10 * (h10 / 3 + 1), o13.x + 1.4 * Math.cos(v12) * p10 * (h10 / 3 + 1), o13.y + 1.4 * Math.sin(v12) * p10 * (h10 / 3 + 1)];
  }, rs.findCompoundLoopPoints = function(e22, t17, n13, r10) {
    var a10 = e22._private.rscratch;
    a10.edgeType = "compound";
    var i11 = t17.srcPos, o13 = t17.tgtPos, s11 = t17.srcW, l11 = t17.srcH, u10 = t17.tgtW, c10 = t17.tgtH, d12 = e22.pstyle("control-point-step-size").pfValue, h10 = e22.pstyle("control-point-distances"), p10 = h10 ? h10.pfValue[0] : void 0, f11 = n13, g9 = d12;
    r10 && (f11 = 0, g9 = p10);
    var v12 = { x: i11.x - s11 / 2, y: i11.y - l11 / 2 }, y10 = { x: o13.x - u10 / 2, y: o13.y - c10 / 2 }, m12 = { x: Math.min(v12.x, y10.x), y: Math.min(v12.y, y10.y) }, b11 = Math.max(0.5, Math.log(0.01 * s11)), x11 = Math.max(0.5, Math.log(0.01 * u10));
    a10.ctrlpts = [m12.x, m12.y - (1 + Math.pow(50, 1.12) / 100) * g9 * (f11 / 3 + 1) * b11, m12.x - (1 + Math.pow(50, 1.12) / 100) * g9 * (f11 / 3 + 1) * x11, m12.y];
  }, rs.findStraightEdgePoints = function(e22) {
    e22._private.rscratch.edgeType = "straight";
  }, rs.findBezierPoints = function(e22, t17, n13, r10, a10) {
    var i11 = e22._private.rscratch, o13 = t17.vectorNormInverse, s11 = t17.posPts, l11 = t17.intersectionPts, u10 = e22.pstyle("edge-distances").value, c10 = e22.pstyle("control-point-step-size").pfValue, d12 = e22.pstyle("control-point-distances"), h10 = e22.pstyle("control-point-weights"), p10 = d12 && h10 ? Math.min(d12.value.length, h10.value.length) : 1, f11 = d12 ? d12.pfValue[0] : void 0, g9 = h10.value[0], v12 = r10;
    i11.edgeType = v12 ? "multibezier" : "bezier", i11.ctrlpts = [];
    for (var y10 = 0; y10 < p10; y10++) {
      var m12 = (0.5 - t17.eles.length / 2 + n13) * c10 * (a10 ? -1 : 1), b11 = void 0, x11 = ut4(m12);
      v12 && (f11 = d12 ? d12.pfValue[y10] : c10, g9 = h10.value[y10]);
      var w10 = void 0 !== (b11 = r10 ? f11 : void 0 !== f11 ? x11 * f11 : void 0) ? b11 : m12, E10 = 1 - g9, k10 = g9, C9 = "node-position" === u10 ? s11 : l11, S8 = { x: C9.x1 * E10 + C9.x2 * k10, y: C9.y1 * E10 + C9.y2 * k10 };
      i11.ctrlpts.push(S8.x + o13.x * w10, S8.y + o13.y * w10);
    }
  }, rs.findTaxiPoints = function(e22, t17) {
    var n13 = e22._private.rscratch;
    n13.edgeType = "segments";
    var r10 = "vertical", a10 = "horizontal", i11 = "leftward", o13 = "rightward", s11 = "downward", l11 = "upward", u10 = t17.posPts, c10 = t17.srcW, d12 = t17.srcH, h10 = t17.tgtW, p10 = t17.tgtH, f11 = "node-position" !== e22.pstyle("edge-distances").value, g9 = e22.pstyle("taxi-direction").value, v12 = g9, y10 = e22.pstyle("taxi-turn"), m12 = "%" === y10.units, b11 = y10.pfValue, x11 = b11 < 0, w10 = e22.pstyle("taxi-turn-min-distance").pfValue, E10 = f11 ? (c10 + h10) / 2 : 0, k10 = f11 ? (d12 + p10) / 2 : 0, C9 = u10.x2 - u10.x1, S8 = u10.y2 - u10.y1, D7 = function(e23, t18) {
      return e23 > 0 ? Math.max(e23 - t18, 0) : Math.min(e23 + t18, 0);
    }, P10 = D7(C9, E10), T9 = D7(S8, k10), M9 = false;
    "auto" === v12 ? g9 = Math.abs(P10) > Math.abs(T9) ? a10 : r10 : v12 === l11 || v12 === s11 ? (g9 = r10, M9 = true) : v12 !== i11 && v12 !== o13 || (g9 = a10, M9 = true);
    var B8, _7 = g9 === r10, N8 = _7 ? T9 : P10, I8 = _7 ? S8 : C9, z8 = ut4(I8), L10 = false;
    (M9 && (m12 || x11) || !(v12 === s11 && I8 < 0 || v12 === l11 && I8 > 0 || v12 === i11 && I8 > 0 || v12 === o13 && I8 < 0) || (N8 = (z8 *= -1) * Math.abs(N8), L10 = true), m12) ? B8 = (b11 < 0 ? 1 + b11 : b11) * N8 : B8 = (b11 < 0 ? N8 : 0) + b11 * z8;
    var A10 = function(e23) {
      return Math.abs(e23) < w10 || Math.abs(e23) >= Math.abs(N8);
    }, O9 = A10(B8), R8 = A10(Math.abs(N8) - Math.abs(B8));
    if ((O9 || R8) && !L10)
      if (_7) {
        var V8 = Math.abs(I8) <= d12 / 2, F9 = Math.abs(C9) <= h10 / 2;
        if (V8) {
          var q8 = (u10.x1 + u10.x2) / 2, j9 = u10.y1, Y6 = u10.y2;
          n13.segpts = [q8, j9, q8, Y6];
        } else if (F9) {
          var X6 = (u10.y1 + u10.y2) / 2, W8 = u10.x1, H8 = u10.x2;
          n13.segpts = [W8, X6, H8, X6];
        } else
          n13.segpts = [u10.x1, u10.y2];
      } else {
        var K6 = Math.abs(I8) <= c10 / 2, G6 = Math.abs(S8) <= p10 / 2;
        if (K6) {
          var U7 = (u10.y1 + u10.y2) / 2, Z6 = u10.x1, $8 = u10.x2;
          n13.segpts = [Z6, U7, $8, U7];
        } else if (G6) {
          var Q6 = (u10.x1 + u10.x2) / 2, J6 = u10.y1, ee3 = u10.y2;
          n13.segpts = [Q6, J6, Q6, ee3];
        } else
          n13.segpts = [u10.x2, u10.y1];
      }
    else if (_7) {
      var te3 = u10.y1 + B8 + (f11 ? d12 / 2 * z8 : 0), ne3 = u10.x1, re3 = u10.x2;
      n13.segpts = [ne3, te3, re3, te3];
    } else {
      var ae3 = u10.x1 + B8 + (f11 ? c10 / 2 * z8 : 0), ie3 = u10.y1, oe3 = u10.y2;
      n13.segpts = [ae3, ie3, ae3, oe3];
    }
  }, rs.tryToCorrectInvalidPoints = function(e22, t17) {
    var n13 = e22._private.rscratch;
    if ("bezier" === n13.edgeType) {
      var r10 = t17.srcPos, a10 = t17.tgtPos, i11 = t17.srcW, o13 = t17.srcH, s11 = t17.tgtW, l11 = t17.tgtH, u10 = t17.srcShape, c10 = t17.tgtShape, d12 = !I6(n13.startX) || !I6(n13.startY), h10 = !I6(n13.arrowStartX) || !I6(n13.arrowStartY), p10 = !I6(n13.endX) || !I6(n13.endY), f11 = !I6(n13.arrowEndX) || !I6(n13.arrowEndY), g9 = 3 * (this.getArrowWidth(e22.pstyle("width").pfValue, e22.pstyle("arrow-scale").value) * this.arrowShapeWidth), v12 = ct4({ x: n13.ctrlpts[0], y: n13.ctrlpts[1] }, { x: n13.startX, y: n13.startY }), y10 = v12 < g9, m12 = ct4({ x: n13.ctrlpts[0], y: n13.ctrlpts[1] }, { x: n13.endX, y: n13.endY }), b11 = m12 < g9, x11 = false;
      if (d12 || h10 || y10) {
        x11 = true;
        var w10 = { x: n13.ctrlpts[0] - r10.x, y: n13.ctrlpts[1] - r10.y }, E10 = Math.sqrt(w10.x * w10.x + w10.y * w10.y), k10 = { x: w10.x / E10, y: w10.y / E10 }, C9 = Math.max(i11, o13), S8 = { x: n13.ctrlpts[0] + 2 * k10.x * C9, y: n13.ctrlpts[1] + 2 * k10.y * C9 }, D7 = u10.intersectLine(r10.x, r10.y, i11, o13, S8.x, S8.y, 0);
        y10 ? (n13.ctrlpts[0] = n13.ctrlpts[0] + k10.x * (g9 - v12), n13.ctrlpts[1] = n13.ctrlpts[1] + k10.y * (g9 - v12)) : (n13.ctrlpts[0] = D7[0] + k10.x * g9, n13.ctrlpts[1] = D7[1] + k10.y * g9);
      }
      if (p10 || f11 || b11) {
        x11 = true;
        var P10 = { x: n13.ctrlpts[0] - a10.x, y: n13.ctrlpts[1] - a10.y }, T9 = Math.sqrt(P10.x * P10.x + P10.y * P10.y), M9 = { x: P10.x / T9, y: P10.y / T9 }, B8 = Math.max(i11, o13), _7 = { x: n13.ctrlpts[0] + 2 * M9.x * B8, y: n13.ctrlpts[1] + 2 * M9.y * B8 }, N8 = c10.intersectLine(a10.x, a10.y, s11, l11, _7.x, _7.y, 0);
        b11 ? (n13.ctrlpts[0] = n13.ctrlpts[0] + M9.x * (g9 - m12), n13.ctrlpts[1] = n13.ctrlpts[1] + M9.y * (g9 - m12)) : (n13.ctrlpts[0] = N8[0] + M9.x * g9, n13.ctrlpts[1] = N8[1] + M9.y * g9);
      }
      x11 && this.findEndpoints(e22);
    }
  }, rs.storeAllpts = function(e22) {
    var t17 = e22._private.rscratch;
    if ("multibezier" === t17.edgeType || "bezier" === t17.edgeType || "self" === t17.edgeType || "compound" === t17.edgeType) {
      t17.allpts = [], t17.allpts.push(t17.startX, t17.startY);
      for (var n13 = 0; n13 + 1 < t17.ctrlpts.length; n13 += 2)
        t17.allpts.push(t17.ctrlpts[n13], t17.ctrlpts[n13 + 1]), n13 + 3 < t17.ctrlpts.length && t17.allpts.push((t17.ctrlpts[n13] + t17.ctrlpts[n13 + 2]) / 2, (t17.ctrlpts[n13 + 1] + t17.ctrlpts[n13 + 3]) / 2);
      var r10;
      t17.allpts.push(t17.endX, t17.endY), t17.ctrlpts.length / 2 % 2 == 0 ? (r10 = t17.allpts.length / 2 - 1, t17.midX = t17.allpts[r10], t17.midY = t17.allpts[r10 + 1]) : (r10 = t17.allpts.length / 2 - 3, 0.5, t17.midX = pt4(t17.allpts[r10], t17.allpts[r10 + 2], t17.allpts[r10 + 4], 0.5), t17.midY = pt4(t17.allpts[r10 + 1], t17.allpts[r10 + 3], t17.allpts[r10 + 5], 0.5));
    } else if ("straight" === t17.edgeType)
      t17.allpts = [t17.startX, t17.startY, t17.endX, t17.endY], t17.midX = (t17.startX + t17.endX + t17.arrowStartX + t17.arrowEndX) / 4, t17.midY = (t17.startY + t17.endY + t17.arrowStartY + t17.arrowEndY) / 4;
    else if ("segments" === t17.edgeType)
      if (t17.allpts = [], t17.allpts.push(t17.startX, t17.startY), t17.allpts.push.apply(t17.allpts, t17.segpts), t17.allpts.push(t17.endX, t17.endY), t17.segpts.length % 4 == 0) {
        var a10 = t17.segpts.length / 2, i11 = a10 - 2;
        t17.midX = (t17.segpts[i11] + t17.segpts[a10]) / 2, t17.midY = (t17.segpts[i11 + 1] + t17.segpts[a10 + 1]) / 2;
      } else {
        var o13 = t17.segpts.length / 2 - 1;
        t17.midX = t17.segpts[o13], t17.midY = t17.segpts[o13 + 1];
      }
  }, rs.checkForInvalidEdgeWarning = function(e22) {
    var t17 = e22[0]._private.rscratch;
    t17.nodesOverlap || I6(t17.startX) && I6(t17.startY) && I6(t17.endX) && I6(t17.endY) ? t17.loggedErr = false : t17.loggedErr || (t17.loggedErr = true, Me("Edge `" + e22.id() + "` has invalid endpoints and so it is impossible to draw.  Adjust your edge style (e.g. control points) accordingly or use an alternative edge type.  This is expected behaviour when the source node and the target node overlap."));
  }, rs.findEdgeControlPoints = function(e22) {
    var t17 = this;
    if (e22 && 0 !== e22.length) {
      for (var n13 = this, r10 = n13.cy.hasCompoundNodes(), a10 = { map: new Ve(), get: function(e23) {
        var t18 = this.map.get(e23[0]);
        return null != t18 ? t18.get(e23[1]) : null;
      }, set: function(e23, t18) {
        var n14 = this.map.get(e23[0]);
        null == n14 && (n14 = new Ve(), this.map.set(e23[0], n14)), n14.set(e23[1], t18);
      } }, i11 = [], o13 = [], s11 = 0; s11 < e22.length; s11++) {
        var l11 = e22[s11], u10 = l11._private, c10 = l11.pstyle("curve-style").value;
        if (!l11.removed() && l11.takesUpSpace())
          if ("haystack" !== c10) {
            var d12 = "unbundled-bezier" === c10 || "segments" === c10 || "straight" === c10 || "straight-triangle" === c10 || "taxi" === c10, h10 = "unbundled-bezier" === c10 || "bezier" === c10, p10 = u10.source, f11 = u10.target, g9 = [p10.poolIndex(), f11.poolIndex()].sort(), v12 = a10.get(g9);
            null == v12 && (v12 = { eles: [] }, a10.set(g9, v12), i11.push(g9)), v12.eles.push(l11), d12 && (v12.hasUnbundled = true), h10 && (v12.hasBezier = true);
          } else
            o13.push(l11);
      }
      for (var y10 = function(e23) {
        var o14 = i11[e23], s12 = a10.get(o14), l12 = void 0;
        if (!s12.hasUnbundled) {
          var u11 = s12.eles[0].parallelEdges().filter(function(e24) {
            return e24.isBundledBezier();
          });
          Ae(s12.eles), u11.forEach(function(e24) {
            return s12.eles.push(e24);
          }), s12.eles.sort(function(e24, t18) {
            return e24.poolIndex() - t18.poolIndex();
          });
        }
        var c11 = s12.eles[0], d13 = c11.source(), h11 = c11.target();
        if (d13.poolIndex() > h11.poolIndex()) {
          var p11 = d13;
          d13 = h11, h11 = p11;
        }
        var f12 = s12.srcPos = d13.position(), g10 = s12.tgtPos = h11.position(), v13 = s12.srcW = d13.outerWidth(), y11 = s12.srcH = d13.outerHeight(), m13 = s12.tgtW = h11.outerWidth(), b11 = s12.tgtH = h11.outerHeight(), x11 = s12.srcShape = n13.nodeShapes[t17.getNodeShape(d13)], w10 = s12.tgtShape = n13.nodeShapes[t17.getNodeShape(h11)];
        s12.dirCounts = { north: 0, west: 0, south: 0, east: 0, northwest: 0, southwest: 0, northeast: 0, southeast: 0 };
        for (var E10 = 0; E10 < s12.eles.length; E10++) {
          var k10 = s12.eles[E10], C9 = k10[0]._private.rscratch, S8 = k10.pstyle("curve-style").value, D7 = "unbundled-bezier" === S8 || "segments" === S8 || "taxi" === S8, P10 = !d13.same(k10.source());
          if (!s12.calculatedIntersection && d13 !== h11 && (s12.hasBezier || s12.hasUnbundled)) {
            s12.calculatedIntersection = true;
            var T9 = x11.intersectLine(f12.x, f12.y, v13, y11, g10.x, g10.y, 0), M9 = s12.srcIntn = T9, B8 = w10.intersectLine(g10.x, g10.y, m13, b11, f12.x, f12.y, 0), _7 = s12.tgtIntn = B8, N8 = s12.intersectionPts = { x1: T9[0], x2: B8[0], y1: T9[1], y2: B8[1] }, z8 = s12.posPts = { x1: f12.x, x2: g10.x, y1: f12.y, y2: g10.y }, L10 = B8[1] - T9[1], A10 = B8[0] - T9[0], O9 = Math.sqrt(A10 * A10 + L10 * L10), R8 = s12.vector = { x: A10, y: L10 }, V8 = s12.vectorNorm = { x: R8.x / O9, y: R8.y / O9 }, F9 = { x: -V8.y, y: V8.x };
            s12.nodesOverlap = !I6(O9) || w10.checkPoint(T9[0], T9[1], 0, m13, b11, g10.x, g10.y) || x11.checkPoint(B8[0], B8[1], 0, v13, y11, f12.x, f12.y), s12.vectorNormInverse = F9, l12 = { nodesOverlap: s12.nodesOverlap, dirCounts: s12.dirCounts, calculatedIntersection: true, hasBezier: s12.hasBezier, hasUnbundled: s12.hasUnbundled, eles: s12.eles, srcPos: g10, tgtPos: f12, srcW: m13, srcH: b11, tgtW: v13, tgtH: y11, srcIntn: _7, tgtIntn: M9, srcShape: w10, tgtShape: x11, posPts: { x1: z8.x2, y1: z8.y2, x2: z8.x1, y2: z8.y1 }, intersectionPts: { x1: N8.x2, y1: N8.y2, x2: N8.x1, y2: N8.y1 }, vector: { x: -R8.x, y: -R8.y }, vectorNorm: { x: -V8.x, y: -V8.y }, vectorNormInverse: { x: -F9.x, y: -F9.y } };
          }
          var q8 = P10 ? l12 : s12;
          C9.nodesOverlap = q8.nodesOverlap, C9.srcIntn = q8.srcIntn, C9.tgtIntn = q8.tgtIntn, r10 && (d13.isParent() || d13.isChild() || h11.isParent() || h11.isChild()) && (d13.parents().anySame(h11) || h11.parents().anySame(d13) || d13.same(h11) && d13.isParent()) ? t17.findCompoundLoopPoints(k10, q8, E10, D7) : d13 === h11 ? t17.findLoopPoints(k10, q8, E10, D7) : "segments" === S8 ? t17.findSegmentsPoints(k10, q8) : "taxi" === S8 ? t17.findTaxiPoints(k10, q8) : "straight" === S8 || !D7 && s12.eles.length % 2 == 1 && E10 === Math.floor(s12.eles.length / 2) ? t17.findStraightEdgePoints(k10) : t17.findBezierPoints(k10, q8, E10, D7, P10), t17.findEndpoints(k10), t17.tryToCorrectInvalidPoints(k10, q8), t17.checkForInvalidEdgeWarning(k10), t17.storeAllpts(k10), t17.storeEdgeProjections(k10), t17.calculateArrowAngles(k10), t17.recalculateEdgeLabelProjections(k10), t17.calculateLabelAngles(k10);
        }
      }, m12 = 0; m12 < i11.length; m12++)
        y10(m12);
      this.findHaystackPoints(o13);
    }
  }, rs.getSegmentPoints = function(e22) {
    var t17 = e22[0]._private.rscratch;
    if ("segments" === t17.edgeType)
      return this.recalculateRenderedStyle(e22), as(t17.segpts);
  }, rs.getControlPoints = function(e22) {
    var t17 = e22[0]._private.rscratch, n13 = t17.edgeType;
    if ("bezier" === n13 || "multibezier" === n13 || "self" === n13 || "compound" === n13)
      return this.recalculateRenderedStyle(e22), as(t17.ctrlpts);
  }, rs.getEdgeMidpoint = function(e22) {
    var t17 = e22[0]._private.rscratch;
    return this.recalculateRenderedStyle(e22), { x: t17.midX, y: t17.midY };
  };
  var is = { manualEndptToPx: function(e22, t17) {
    var n13 = e22.position(), r10 = e22.outerWidth(), a10 = e22.outerHeight();
    if (2 === t17.value.length) {
      var i11 = [t17.pfValue[0], t17.pfValue[1]];
      return "%" === t17.units[0] && (i11[0] = i11[0] * r10), "%" === t17.units[1] && (i11[1] = i11[1] * a10), i11[0] += n13.x, i11[1] += n13.y, i11;
    }
    var o13 = t17.pfValue[0];
    o13 = -Math.PI / 2 + o13;
    var s11 = 2 * Math.max(r10, a10), l11 = [n13.x + Math.cos(o13) * s11, n13.y + Math.sin(o13) * s11];
    return this.nodeShapes[this.getNodeShape(e22)].intersectLine(n13.x, n13.y, r10, a10, l11[0], l11[1], 0);
  }, findEndpoints: function(e22) {
    var t17, n13, r10, a10, i11, o13 = this, s11 = e22.source()[0], l11 = e22.target()[0], u10 = s11.position(), c10 = l11.position(), d12 = e22.pstyle("target-arrow-shape").value, h10 = e22.pstyle("source-arrow-shape").value, p10 = e22.pstyle("target-distance-from-node").pfValue, f11 = e22.pstyle("source-distance-from-node").pfValue, g9 = e22.pstyle("curve-style").value, v12 = e22._private.rscratch, y10 = v12.edgeType, m12 = "self" === y10 || "compound" === y10, b11 = "bezier" === y10 || "multibezier" === y10 || m12, x11 = "bezier" !== y10, w10 = "straight" === y10 || "segments" === y10, E10 = "segments" === y10, k10 = b11 || x11 || w10, C9 = m12 || "taxi" === g9, S8 = e22.pstyle("source-endpoint"), D7 = C9 ? "outside-to-node" : S8.value, P10 = e22.pstyle("target-endpoint"), T9 = C9 ? "outside-to-node" : P10.value;
    if (v12.srcManEndpt = S8, v12.tgtManEndpt = P10, b11) {
      var M9 = [v12.ctrlpts[0], v12.ctrlpts[1]];
      n13 = x11 ? [v12.ctrlpts[v12.ctrlpts.length - 2], v12.ctrlpts[v12.ctrlpts.length - 1]] : M9, r10 = M9;
    } else if (w10) {
      var B8 = E10 ? v12.segpts.slice(0, 2) : [c10.x, c10.y];
      n13 = E10 ? v12.segpts.slice(v12.segpts.length - 2) : [u10.x, u10.y], r10 = B8;
    }
    if ("inside-to-node" === T9)
      t17 = [c10.x, c10.y];
    else if (P10.units)
      t17 = this.manualEndptToPx(l11, P10);
    else if ("outside-to-line" === T9)
      t17 = v12.tgtIntn;
    else if ("outside-to-node" === T9 || "outside-to-node-or-label" === T9 ? a10 = n13 : "outside-to-line" !== T9 && "outside-to-line-or-label" !== T9 || (a10 = [u10.x, u10.y]), t17 = o13.nodeShapes[this.getNodeShape(l11)].intersectLine(c10.x, c10.y, l11.outerWidth(), l11.outerHeight(), a10[0], a10[1], 0), "outside-to-node-or-label" === T9 || "outside-to-line-or-label" === T9) {
      var _7 = l11._private.rscratch, N8 = _7.labelWidth, z8 = _7.labelHeight, L10 = _7.labelX, A10 = _7.labelY, O9 = N8 / 2, R8 = z8 / 2, V8 = l11.pstyle("text-valign").value;
      "top" === V8 ? A10 -= R8 : "bottom" === V8 && (A10 += R8);
      var F9 = l11.pstyle("text-halign").value;
      "left" === F9 ? L10 -= O9 : "right" === F9 && (L10 += O9);
      var q8 = Ot4(a10[0], a10[1], [L10 - O9, A10 - R8, L10 + O9, A10 - R8, L10 + O9, A10 + R8, L10 - O9, A10 + R8], c10.x, c10.y);
      if (q8.length > 0) {
        var j9 = u10, Y6 = dt4(j9, ot4(t17)), X6 = dt4(j9, ot4(q8)), W8 = Y6;
        if (X6 < Y6 && (t17 = q8, W8 = X6), q8.length > 2)
          dt4(j9, { x: q8[2], y: q8[3] }) < W8 && (t17 = [q8[2], q8[3]]);
      }
    }
    var H8 = Rt4(t17, n13, o13.arrowShapes[d12].spacing(e22) + p10), K6 = Rt4(t17, n13, o13.arrowShapes[d12].gap(e22) + p10);
    if (v12.endX = K6[0], v12.endY = K6[1], v12.arrowEndX = H8[0], v12.arrowEndY = H8[1], "inside-to-node" === D7)
      t17 = [u10.x, u10.y];
    else if (S8.units)
      t17 = this.manualEndptToPx(s11, S8);
    else if ("outside-to-line" === D7)
      t17 = v12.srcIntn;
    else if ("outside-to-node" === D7 || "outside-to-node-or-label" === D7 ? i11 = r10 : "outside-to-line" !== D7 && "outside-to-line-or-label" !== D7 || (i11 = [c10.x, c10.y]), t17 = o13.nodeShapes[this.getNodeShape(s11)].intersectLine(u10.x, u10.y, s11.outerWidth(), s11.outerHeight(), i11[0], i11[1], 0), "outside-to-node-or-label" === D7 || "outside-to-line-or-label" === D7) {
      var G6 = s11._private.rscratch, U7 = G6.labelWidth, Z6 = G6.labelHeight, $8 = G6.labelX, Q6 = G6.labelY, J6 = U7 / 2, ee3 = Z6 / 2, te3 = s11.pstyle("text-valign").value;
      "top" === te3 ? Q6 -= ee3 : "bottom" === te3 && (Q6 += ee3);
      var ne3 = s11.pstyle("text-halign").value;
      "left" === ne3 ? $8 -= J6 : "right" === ne3 && ($8 += J6);
      var re3 = Ot4(i11[0], i11[1], [$8 - J6, Q6 - ee3, $8 + J6, Q6 - ee3, $8 + J6, Q6 + ee3, $8 - J6, Q6 + ee3], u10.x, u10.y);
      if (re3.length > 0) {
        var ae3 = c10, ie3 = dt4(ae3, ot4(t17)), oe3 = dt4(ae3, ot4(re3)), se3 = ie3;
        if (oe3 < ie3 && (t17 = [re3[0], re3[1]], se3 = oe3), re3.length > 2)
          dt4(ae3, { x: re3[2], y: re3[3] }) < se3 && (t17 = [re3[2], re3[3]]);
      }
    }
    var le3 = Rt4(t17, r10, o13.arrowShapes[h10].spacing(e22) + f11), ue3 = Rt4(t17, r10, o13.arrowShapes[h10].gap(e22) + f11);
    v12.startX = ue3[0], v12.startY = ue3[1], v12.arrowStartX = le3[0], v12.arrowStartY = le3[1], k10 && (I6(v12.startX) && I6(v12.startY) && I6(v12.endX) && I6(v12.endY) ? v12.badLine = false : v12.badLine = true);
  }, getSourceEndpoint: function(e22) {
    var t17 = e22[0]._private.rscratch;
    return this.recalculateRenderedStyle(e22), "haystack" === t17.edgeType ? { x: t17.haystackPts[0], y: t17.haystackPts[1] } : { x: t17.arrowStartX, y: t17.arrowStartY };
  }, getTargetEndpoint: function(e22) {
    var t17 = e22[0]._private.rscratch;
    return this.recalculateRenderedStyle(e22), "haystack" === t17.edgeType ? { x: t17.haystackPts[2], y: t17.haystackPts[3] } : { x: t17.arrowEndX, y: t17.arrowEndY };
  } };
  var os = {};
  function ss(e22, t17, n13) {
    for (var r10 = function(e23, t18, n14, r11) {
      return pt4(e23, t18, n14, r11);
    }, a10 = t17._private.rstyle.bezierPts, i11 = 0; i11 < e22.bezierProjPcts.length; i11++) {
      var o13 = e22.bezierProjPcts[i11];
      a10.push({ x: r10(n13[0], n13[2], n13[4], o13), y: r10(n13[1], n13[3], n13[5], o13) });
    }
  }
  os.storeEdgeProjections = function(e22) {
    var t17 = e22._private, n13 = t17.rscratch, r10 = n13.edgeType;
    if (t17.rstyle.bezierPts = null, t17.rstyle.linePts = null, t17.rstyle.haystackPts = null, "multibezier" === r10 || "bezier" === r10 || "self" === r10 || "compound" === r10) {
      t17.rstyle.bezierPts = [];
      for (var a10 = 0; a10 + 5 < n13.allpts.length; a10 += 4)
        ss(this, e22, n13.allpts.slice(a10, a10 + 6));
    } else if ("segments" === r10) {
      var i11 = t17.rstyle.linePts = [];
      for (a10 = 0; a10 + 1 < n13.allpts.length; a10 += 2)
        i11.push({ x: n13.allpts[a10], y: n13.allpts[a10 + 1] });
    } else if ("haystack" === r10) {
      var o13 = n13.haystackPts;
      t17.rstyle.haystackPts = [{ x: o13[0], y: o13[1] }, { x: o13[2], y: o13[3] }];
    }
    t17.rstyle.arrowWidth = this.getArrowWidth(e22.pstyle("width").pfValue, e22.pstyle("arrow-scale").value) * this.arrowShapeWidth;
  }, os.recalculateEdgeProjections = function(e22) {
    this.findEdgeControlPoints(e22);
  };
  var ls = { recalculateNodeLabelProjection: function(e22) {
    var t17 = e22.pstyle("label").strValue;
    if (!F6(t17)) {
      var n13, r10, a10 = e22._private, i11 = e22.width(), o13 = e22.height(), s11 = e22.padding(), l11 = e22.position(), u10 = e22.pstyle("text-halign").strValue, c10 = e22.pstyle("text-valign").strValue, d12 = a10.rscratch, h10 = a10.rstyle;
      switch (u10) {
        case "left":
          n13 = l11.x - i11 / 2 - s11;
          break;
        case "right":
          n13 = l11.x + i11 / 2 + s11;
          break;
        default:
          n13 = l11.x;
      }
      switch (c10) {
        case "top":
          r10 = l11.y - o13 / 2 - s11;
          break;
        case "bottom":
          r10 = l11.y + o13 / 2 + s11;
          break;
        default:
          r10 = l11.y;
      }
      d12.labelX = n13, d12.labelY = r10, h10.labelX = n13, h10.labelY = r10, this.calculateLabelAngles(e22), this.applyLabelDimensions(e22);
    }
  } };
  var us = function(e22, t17) {
    var n13 = Math.atan(t17 / e22);
    return 0 === e22 && n13 < 0 && (n13 *= -1), n13;
  };
  var cs = function(e22, t17) {
    var n13 = t17.x - e22.x, r10 = t17.y - e22.y;
    return us(n13, r10);
  };
  ls.recalculateEdgeLabelProjections = function(e22) {
    var t17, n13 = e22._private, r10 = n13.rscratch, a10 = this, i11 = { mid: e22.pstyle("label").strValue, source: e22.pstyle("source-label").strValue, target: e22.pstyle("target-label").strValue };
    if (i11.mid || i11.source || i11.target) {
      t17 = { x: r10.midX, y: r10.midY };
      var o13 = function(e23, t18, r11) {
        Re(n13.rscratch, e23, t18, r11), Re(n13.rstyle, e23, t18, r11);
      };
      o13("labelX", null, t17.x), o13("labelY", null, t17.y);
      var s11 = us(r10.midDispX, r10.midDispY);
      o13("labelAutoAngle", null, s11);
      var l11 = function e23() {
        if (e23.cache)
          return e23.cache;
        for (var t18 = [], i12 = 0; i12 + 5 < r10.allpts.length; i12 += 4) {
          var o14 = { x: r10.allpts[i12], y: r10.allpts[i12 + 1] }, s12 = { x: r10.allpts[i12 + 2], y: r10.allpts[i12 + 3] }, l12 = { x: r10.allpts[i12 + 4], y: r10.allpts[i12 + 5] };
          t18.push({ p0: o14, p1: s12, p2: l12, startDist: 0, length: 0, segments: [] });
        }
        var u11 = n13.rstyle.bezierPts, c10 = a10.bezierProjPcts.length;
        function d12(e24, t19, n14, r11, a11) {
          var i13 = ct4(t19, n14), o15 = e24.segments[e24.segments.length - 1], s13 = { p0: t19, p1: n14, t0: r11, t1: a11, startDist: o15 ? o15.startDist + o15.length : 0, length: i13 };
          e24.segments.push(s13), e24.length += i13;
        }
        for (var h10 = 0; h10 < t18.length; h10++) {
          var p10 = t18[h10], f11 = t18[h10 - 1];
          f11 && (p10.startDist = f11.startDist + f11.length), d12(p10, p10.p0, u11[h10 * c10], 0, a10.bezierProjPcts[0]);
          for (var g9 = 0; g9 < c10 - 1; g9++)
            d12(p10, u11[h10 * c10 + g9], u11[h10 * c10 + g9 + 1], a10.bezierProjPcts[g9], a10.bezierProjPcts[g9 + 1]);
          d12(p10, u11[h10 * c10 + c10 - 1], p10.p2, a10.bezierProjPcts[c10 - 1], 1);
        }
        return e23.cache = t18;
      }, u10 = function(n14) {
        var a11, s12 = "source" === n14;
        if (i11[n14]) {
          var u11 = e22.pstyle(n14 + "-text-offset").pfValue;
          switch (r10.edgeType) {
            case "self":
            case "compound":
            case "bezier":
            case "multibezier":
              for (var c10, d12 = l11(), h10 = 0, p10 = 0, f11 = 0; f11 < d12.length; f11++) {
                for (var g9 = d12[s12 ? f11 : d12.length - 1 - f11], v12 = 0; v12 < g9.segments.length; v12++) {
                  var y10 = g9.segments[s12 ? v12 : g9.segments.length - 1 - v12], m12 = f11 === d12.length - 1 && v12 === g9.segments.length - 1;
                  if (h10 = p10, (p10 += y10.length) >= u11 || m12) {
                    c10 = { cp: g9, segment: y10 };
                    break;
                  }
                }
                if (c10)
                  break;
              }
              var b11 = c10.cp, x11 = c10.segment, w10 = (u11 - h10) / x11.length, E10 = x11.t1 - x11.t0, k10 = s12 ? x11.t0 + E10 * w10 : x11.t1 - E10 * w10;
              k10 = gt4(0, k10, 1), t17 = ft4(b11.p0, b11.p1, b11.p2, k10), a11 = function(e23, t18, n15, r11) {
                var a12 = gt4(0, r11 - 1e-3, 1), i12 = gt4(0, r11 + 1e-3, 1), o14 = ft4(e23, t18, n15, a12), s13 = ft4(e23, t18, n15, i12);
                return cs(o14, s13);
              }(b11.p0, b11.p1, b11.p2, k10);
              break;
            case "straight":
            case "segments":
            case "haystack":
              for (var C9, S8, D7, P10, T9 = 0, M9 = r10.allpts.length, B8 = 0; B8 + 3 < M9 && (s12 ? (D7 = { x: r10.allpts[B8], y: r10.allpts[B8 + 1] }, P10 = { x: r10.allpts[B8 + 2], y: r10.allpts[B8 + 3] }) : (D7 = { x: r10.allpts[M9 - 2 - B8], y: r10.allpts[M9 - 1 - B8] }, P10 = { x: r10.allpts[M9 - 4 - B8], y: r10.allpts[M9 - 3 - B8] }), S8 = T9, !((T9 += C9 = ct4(D7, P10)) >= u11)); B8 += 2)
                ;
              var _7 = (u11 - S8) / C9;
              _7 = gt4(0, _7, 1), t17 = function(e23, t18, n15, r11) {
                var a12 = t18.x - e23.x, i12 = t18.y - e23.y, o14 = ct4(e23, t18), s13 = a12 / o14, l12 = i12 / o14;
                return n15 = null == n15 ? 0 : n15, r11 = null != r11 ? r11 : n15 * o14, { x: e23.x + s13 * r11, y: e23.y + l12 * r11 };
              }(D7, P10, _7), a11 = cs(D7, P10);
          }
          o13("labelX", n14, t17.x), o13("labelY", n14, t17.y), o13("labelAutoAngle", n14, a11);
        }
      };
      u10("source"), u10("target"), this.applyLabelDimensions(e22);
    }
  }, ls.applyLabelDimensions = function(e22) {
    this.applyPrefixedLabelDimensions(e22), e22.isEdge() && (this.applyPrefixedLabelDimensions(e22, "source"), this.applyPrefixedLabelDimensions(e22, "target"));
  }, ls.applyPrefixedLabelDimensions = function(e22, t17) {
    var n13 = e22._private, r10 = this.getLabelText(e22, t17), a10 = this.calculateLabelDimensions(e22, r10), i11 = e22.pstyle("line-height").pfValue, o13 = e22.pstyle("text-wrap").strValue, s11 = Oe(n13.rscratch, "labelWrapCachedLines", t17) || [], l11 = "wrap" !== o13 ? 1 : Math.max(s11.length, 1), u10 = a10.height / l11, c10 = u10 * i11, d12 = a10.width, h10 = a10.height + (l11 - 1) * (i11 - 1) * u10;
    Re(n13.rstyle, "labelWidth", t17, d12), Re(n13.rscratch, "labelWidth", t17, d12), Re(n13.rstyle, "labelHeight", t17, h10), Re(n13.rscratch, "labelHeight", t17, h10), Re(n13.rscratch, "labelLineHeight", t17, c10);
  }, ls.getLabelText = function(e22, t17) {
    var n13 = e22._private, r10 = t17 ? t17 + "-" : "", a10 = e22.pstyle(r10 + "label").strValue, i11 = e22.pstyle("text-transform").value, o13 = function(e23, r11) {
      return r11 ? (Re(n13.rscratch, e23, t17, r11), r11) : Oe(n13.rscratch, e23, t17);
    };
    if (!a10)
      return "";
    "none" == i11 || ("uppercase" == i11 ? a10 = a10.toUpperCase() : "lowercase" == i11 && (a10 = a10.toLowerCase()));
    var s11 = e22.pstyle("text-wrap").value;
    if ("wrap" === s11) {
      var l11 = o13("labelKey");
      if (null != l11 && o13("labelWrapKey") === l11)
        return o13("labelWrapCachedText");
      for (var u10 = a10.split("\n"), c10 = e22.pstyle("text-max-width").pfValue, d12 = "anywhere" === e22.pstyle("text-overflow-wrap").value, h10 = [], p10 = /[\s\u200b]+/, f11 = d12 ? "" : " ", g9 = 0; g9 < u10.length; g9++) {
        var v12 = u10[g9], y10 = this.calculateLabelDimensions(e22, v12).width;
        if (d12) {
          var m12 = v12.split("").join("\u200B");
          v12 = m12;
        }
        if (y10 > c10) {
          for (var b11 = v12.split(p10), x11 = "", w10 = 0; w10 < b11.length; w10++) {
            var E10 = b11[w10], k10 = 0 === x11.length ? E10 : x11 + f11 + E10;
            this.calculateLabelDimensions(e22, k10).width <= c10 ? x11 += E10 + f11 : (x11 && h10.push(x11), x11 = E10 + f11);
          }
          x11.match(/^[\s\u200b]+$/) || h10.push(x11);
        } else
          h10.push(v12);
      }
      o13("labelWrapCachedLines", h10), a10 = o13("labelWrapCachedText", h10.join("\n")), o13("labelWrapKey", l11);
    } else if ("ellipsis" === s11) {
      var C9 = e22.pstyle("text-max-width").pfValue, S8 = "", D7 = false;
      if (this.calculateLabelDimensions(e22, a10).width < C9)
        return a10;
      for (var P10 = 0; P10 < a10.length; P10++) {
        if (this.calculateLabelDimensions(e22, S8 + a10[P10] + "\u2026").width > C9)
          break;
        S8 += a10[P10], P10 === a10.length - 1 && (D7 = true);
      }
      return D7 || (S8 += "\u2026"), S8;
    }
    return a10;
  }, ls.getLabelJustification = function(e22) {
    var t17 = e22.pstyle("text-justification").strValue, n13 = e22.pstyle("text-halign").strValue;
    if ("auto" !== t17)
      return t17;
    if (!e22.isNode())
      return "center";
    switch (n13) {
      case "left":
        return "right";
      case "right":
        return "left";
      default:
        return "center";
    }
  }, ls.calculateLabelDimensions = function(e22, t17) {
    var n13 = ve(t17, e22._private.labelDimsKey), r10 = this.labelDimCache || (this.labelDimCache = []), a10 = r10[n13];
    if (null != a10)
      return a10;
    var i11 = e22.pstyle("font-style").strValue, o13 = e22.pstyle("font-size").pfValue, s11 = e22.pstyle("font-family").strValue, l11 = e22.pstyle("font-weight").strValue, u10 = this.labelCalcCanvas, c10 = this.labelCalcCanvasContext;
    if (!u10) {
      u10 = this.labelCalcCanvas = document.createElement("canvas"), c10 = this.labelCalcCanvasContext = u10.getContext("2d");
      var d12 = u10.style;
      d12.position = "absolute", d12.left = "-9999px", d12.top = "-9999px", d12.zIndex = "-1", d12.visibility = "hidden", d12.pointerEvents = "none";
    }
    c10.font = "".concat(i11, " ").concat(l11, " ").concat(o13, "px ").concat(s11);
    for (var h10 = 0, p10 = 0, f11 = t17.split("\n"), g9 = 0; g9 < f11.length; g9++) {
      var v12 = f11[g9], y10 = c10.measureText(v12), m12 = Math.ceil(y10.width), b11 = o13;
      h10 = Math.max(m12, h10), p10 += b11;
    }
    return h10 += 0, p10 += 0, r10[n13] = { width: h10, height: p10 };
  }, ls.calculateLabelAngle = function(e22, t17) {
    var n13 = e22._private.rscratch, r10 = e22.isEdge(), a10 = t17 ? t17 + "-" : "", i11 = e22.pstyle(a10 + "text-rotation"), o13 = i11.strValue;
    return "none" === o13 ? 0 : r10 && "autorotate" === o13 ? n13.labelAutoAngle : "autorotate" === o13 ? 0 : i11.pfValue;
  }, ls.calculateLabelAngles = function(e22) {
    var t17 = this, n13 = e22.isEdge(), r10 = e22._private.rscratch;
    r10.labelAngle = t17.calculateLabelAngle(e22), n13 && (r10.sourceLabelAngle = t17.calculateLabelAngle(e22, "source"), r10.targetLabelAngle = t17.calculateLabelAngle(e22, "target"));
  };
  var ds = {};
  var hs = false;
  ds.getNodeShape = function(e22) {
    var t17 = e22.pstyle("shape").value;
    if ("cutrectangle" === t17 && (e22.width() < 28 || e22.height() < 28))
      return hs || (Me("The `cutrectangle` node shape can not be used at small sizes so `rectangle` is used instead"), hs = true), "rectangle";
    if (e22.isParent())
      return "rectangle" === t17 || "roundrectangle" === t17 || "round-rectangle" === t17 || "cutrectangle" === t17 || "cut-rectangle" === t17 || "barrel" === t17 ? t17 : "rectangle";
    if ("polygon" === t17) {
      var n13 = e22.pstyle("shape-polygon-points").value;
      return this.nodeShapes.makePolygon(n13).name;
    }
    return t17;
  };
  var ps = { registerCalculationListeners: function() {
    var e22 = this.cy, t17 = e22.collection(), n13 = this, r10 = function(e23) {
      var n14 = !(arguments.length > 1 && void 0 !== arguments[1]) || arguments[1];
      if (t17.merge(e23), n14)
        for (var r11 = 0; r11 < e23.length; r11++) {
          var a11 = e23[r11]._private.rstyle;
          a11.clean = false, a11.cleanConnected = false;
        }
    };
    n13.binder(e22).on("bounds.* dirty.*", function(e23) {
      var t18 = e23.target;
      r10(t18);
    }).on("style.* background.*", function(e23) {
      var t18 = e23.target;
      r10(t18, false);
    });
    var a10 = function(a11) {
      if (a11) {
        var i11 = n13.onUpdateEleCalcsFns;
        t17.cleanStyle();
        for (var o13 = 0; o13 < t17.length; o13++) {
          var s11 = t17[o13], l11 = s11._private.rstyle;
          s11.isNode() && !l11.cleanConnected && (r10(s11.connectedEdges()), l11.cleanConnected = true);
        }
        if (i11)
          for (var u10 = 0; u10 < i11.length; u10++) {
            (0, i11[u10])(a11, t17);
          }
        n13.recalculateRenderedStyle(t17), t17 = e22.collection();
      }
    };
    n13.flushRenderedStyleQueue = function() {
      a10(true);
    }, n13.beforeRender(a10, n13.beforeRenderPriorities.eleCalcs);
  }, onUpdateEleCalcs: function(e22) {
    (this.onUpdateEleCalcsFns = this.onUpdateEleCalcsFns || []).push(e22);
  }, recalculateRenderedStyle: function(e22, t17) {
    var n13 = function(e23) {
      return e23._private.rstyle.cleanConnected;
    }, r10 = [], a10 = [];
    if (!this.destroyed) {
      void 0 === t17 && (t17 = true);
      for (var i11 = 0; i11 < e22.length; i11++) {
        var o13 = e22[i11], s11 = o13._private, l11 = s11.rstyle;
        !o13.isEdge() || n13(o13.source()) && n13(o13.target()) || (l11.clean = false), t17 && l11.clean || o13.removed() || "none" !== o13.pstyle("display").value && ("nodes" === s11.group ? a10.push(o13) : r10.push(o13), l11.clean = true);
      }
      for (var u10 = 0; u10 < a10.length; u10++) {
        var c10 = a10[u10], d12 = c10._private.rstyle, h10 = c10.position();
        this.recalculateNodeLabelProjection(c10), d12.nodeX = h10.x, d12.nodeY = h10.y, d12.nodeW = c10.pstyle("width").pfValue, d12.nodeH = c10.pstyle("height").pfValue;
      }
      this.recalculateEdgeProjections(r10);
      for (var p10 = 0; p10 < r10.length; p10++) {
        var f11 = r10[p10]._private, g9 = f11.rstyle, v12 = f11.rscratch;
        g9.srcX = v12.arrowStartX, g9.srcY = v12.arrowStartY, g9.tgtX = v12.arrowEndX, g9.tgtY = v12.arrowEndY, g9.midX = v12.midX, g9.midY = v12.midY, g9.labelAngle = v12.labelAngle, g9.sourceLabelAngle = v12.sourceLabelAngle, g9.targetLabelAngle = v12.targetLabelAngle;
      }
    }
  } };
  var fs = { updateCachedGrabbedEles: function() {
    var e22 = this.cachedZSortedEles;
    if (e22) {
      e22.drag = [], e22.nondrag = [];
      for (var t17 = [], n13 = 0; n13 < e22.length; n13++) {
        var r10 = (a10 = e22[n13])._private.rscratch;
        a10.grabbed() && !a10.isParent() ? t17.push(a10) : r10.inDragLayer ? e22.drag.push(a10) : e22.nondrag.push(a10);
      }
      for (n13 = 0; n13 < t17.length; n13++) {
        var a10 = t17[n13];
        e22.drag.push(a10);
      }
    }
  }, invalidateCachedZSortedEles: function() {
    this.cachedZSortedEles = null;
  }, getCachedZSortedEles: function(e22) {
    if (e22 || !this.cachedZSortedEles) {
      var t17 = this.cy.mutableElements().toArray();
      t17.sort(Qa), t17.interactive = t17.filter(function(e23) {
        return e23.interactive();
      }), this.cachedZSortedEles = t17, this.updateCachedGrabbedEles();
    } else
      t17 = this.cachedZSortedEles;
    return t17;
  } };
  var gs = {};
  [ts, ns, rs, is, os, ls, ds, ps, fs].forEach(function(e22) {
    J4(gs, e22);
  });
  var vs = { getCachedImage: function(e22, t17, n13) {
    var r10 = this.imageCache = this.imageCache || {}, a10 = r10[e22];
    if (a10)
      return a10.image.complete || a10.image.addEventListener("load", n13), a10.image;
    var i11 = (a10 = r10[e22] = r10[e22] || {}).image = new Image();
    i11.addEventListener("load", n13), i11.addEventListener("error", function() {
      i11.error = true;
    });
    var o13 = "data:";
    return e22.substring(0, 5).toLowerCase() === o13 || (t17 = "null" === t17 ? null : t17, i11.crossOrigin = t17), i11.src = e22, i11;
  } };
  var ys = { registerBinding: function(e22, t17, n13, r10) {
    var a10 = Array.prototype.slice.apply(arguments, [1]), i11 = this.binder(e22);
    return i11.on.apply(i11, a10);
  } };
  ys.binder = function(e22) {
    var t17, n13 = this, r10 = n13.cy.window(), a10 = e22 === r10 || e22 === r10.document || e22 === r10.document.body || (t17 = e22, "undefined" != typeof HTMLElement && t17 instanceof HTMLElement);
    if (null == n13.supportsPassiveEvents) {
      var i11 = false;
      try {
        var o13 = Object.defineProperty({}, "passive", { get: function() {
          return i11 = true, true;
        } });
        r10.addEventListener("test", null, o13);
      } catch (e23) {
      }
      n13.supportsPassiveEvents = i11;
    }
    var s11 = function(t18, r11, i12) {
      var o14 = Array.prototype.slice.call(arguments);
      return a10 && n13.supportsPassiveEvents && (o14[2] = { capture: null != i12 && i12, passive: false, once: false }), n13.bindings.push({ target: e22, args: o14 }), (e22.addEventListener || e22.on).apply(e22, o14), this;
    };
    return { on: s11, addEventListener: s11, addListener: s11, bind: s11 };
  }, ys.nodeIsDraggable = function(e22) {
    return e22 && e22.isNode() && !e22.locked() && e22.grabbable();
  }, ys.nodeIsGrabbable = function(e22) {
    return this.nodeIsDraggable(e22) && e22.interactive();
  }, ys.load = function() {
    var e22 = this, t17 = e22.cy.window(), n13 = function(e23) {
      return e23.selected();
    }, r10 = function(t18, n14, r11, a11) {
      null == t18 && (t18 = e22.cy);
      for (var i12 = 0; i12 < n14.length; i12++) {
        var o14 = n14[i12];
        t18.emit({ originalEvent: r11, type: o14, position: a11 });
      }
    }, a10 = function(e23) {
      return e23.shiftKey || e23.metaKey || e23.ctrlKey;
    }, i11 = function(t18, n14) {
      var r11 = true;
      if (e22.cy.hasCompoundNodes() && t18 && t18.pannable())
        for (var a11 = 0; n14 && a11 < n14.length; a11++) {
          if ((t18 = n14[a11]).isNode() && t18.isParent() && !t18.pannable()) {
            r11 = false;
            break;
          }
        }
      else
        r11 = true;
      return r11;
    }, o13 = function(e23) {
      e23[0]._private.rscratch.inDragLayer = true;
    }, s11 = function(e23) {
      e23[0]._private.rscratch.isGrabTarget = true;
    }, l11 = function(e23, t18) {
      var n14 = t18.addToList;
      n14.has(e23) || !e23.grabbable() || e23.locked() || (n14.merge(e23), function(e24) {
        e24[0]._private.grabbed = true;
      }(e23));
    }, u10 = function(t18, n14) {
      n14 = n14 || {};
      var r11 = t18.cy().hasCompoundNodes();
      n14.inDragLayer && (t18.forEach(o13), t18.neighborhood().stdFilter(function(e23) {
        return !r11 || e23.isEdge();
      }).forEach(o13)), n14.addToList && t18.forEach(function(e23) {
        l11(e23, n14);
      }), function(e23, t19) {
        if (e23.cy().hasCompoundNodes() && (null != t19.inDragLayer || null != t19.addToList)) {
          var n15 = e23.descendants();
          t19.inDragLayer && (n15.forEach(o13), n15.connectedEdges().forEach(o13)), t19.addToList && l11(n15, t19);
        }
      }(t18, n14), p10(t18, { inDragLayer: n14.inDragLayer }), e22.updateCachedGrabbedEles();
    }, d12 = u10, h10 = function(t18) {
      t18 && (e22.getCachedZSortedEles().forEach(function(e23) {
        !function(e24) {
          e24[0]._private.grabbed = false;
        }(e23), function(e24) {
          e24[0]._private.rscratch.inDragLayer = false;
        }(e23), function(e24) {
          e24[0]._private.rscratch.isGrabTarget = false;
        }(e23);
      }), e22.updateCachedGrabbedEles());
    }, p10 = function(e23, t18) {
      if ((null != t18.inDragLayer || null != t18.addToList) && e23.cy().hasCompoundNodes()) {
        var n14 = e23.ancestors().orphans();
        if (!n14.same(e23)) {
          var r11 = n14.descendants().spawnSelf().merge(n14).unmerge(e23).unmerge(e23.descendants()), a11 = r11.connectedEdges();
          t18.inDragLayer && (a11.forEach(o13), r11.forEach(o13)), t18.addToList && r11.forEach(function(e24) {
            l11(e24, t18);
          });
        }
      }
    }, f11 = function() {
      null != document.activeElement && null != document.activeElement.blur && document.activeElement.blur();
    }, g9 = "undefined" != typeof MutationObserver, v12 = "undefined" != typeof ResizeObserver;
    g9 ? (e22.removeObserver = new MutationObserver(function(t18) {
      for (var n14 = 0; n14 < t18.length; n14++) {
        var r11 = t18[n14].removedNodes;
        if (r11)
          for (var a11 = 0; a11 < r11.length; a11++) {
            if (r11[a11] === e22.container) {
              e22.destroy();
              break;
            }
          }
      }
    }), e22.container.parentNode && e22.removeObserver.observe(e22.container.parentNode, { childList: true })) : e22.registerBinding(e22.container, "DOMNodeRemoved", function(t18) {
      e22.destroy();
    });
    var y10 = c6.default(function() {
      e22.cy.resize();
    }, 100);
    g9 && (e22.styleObserver = new MutationObserver(y10), e22.styleObserver.observe(e22.container, { attributes: true })), e22.registerBinding(t17, "resize", y10), v12 && (e22.resizeObserver = new ResizeObserver(y10), e22.resizeObserver.observe(e22.container));
    var m12 = function() {
      e22.invalidateContainerClientCoordsCache();
    };
    !function(e23, t18) {
      for (; null != e23; )
        t18(e23), e23 = e23.parentNode;
    }(e22.container, function(t18) {
      e22.registerBinding(t18, "transitionend", m12), e22.registerBinding(t18, "animationend", m12), e22.registerBinding(t18, "scroll", m12);
    }), e22.registerBinding(e22.container, "contextmenu", function(e23) {
      e23.preventDefault();
    });
    var b11, x11, w10, E10 = function(t18) {
      for (var n14 = e22.findContainerClientCoords(), r11 = n14[0], a11 = n14[1], i12 = n14[2], o14 = n14[3], s12 = t18.touches ? t18.touches : [t18], l12 = false, u11 = 0; u11 < s12.length; u11++) {
        var c10 = s12[u11];
        if (r11 <= c10.clientX && c10.clientX <= r11 + i12 && a11 <= c10.clientY && c10.clientY <= a11 + o14) {
          l12 = true;
          break;
        }
      }
      if (!l12)
        return false;
      for (var d13 = e22.container, h11 = t18.target.parentNode, p11 = false; h11; ) {
        if (h11 === d13) {
          p11 = true;
          break;
        }
        h11 = h11.parentNode;
      }
      return !!p11;
    };
    e22.registerBinding(e22.container, "mousedown", function(t18) {
      if (E10(t18)) {
        t18.preventDefault(), f11(), e22.hoverData.capture = true, e22.hoverData.which = t18.which;
        var n14 = e22.cy, a11 = [t18.clientX, t18.clientY], i12 = e22.projectIntoViewport(a11[0], a11[1]), o14 = e22.selection, l12 = e22.findNearestElements(i12[0], i12[1], true, false), c10 = l12[0], h11 = e22.dragData.possibleDragElements;
        e22.hoverData.mdownPos = i12, e22.hoverData.mdownGPos = a11;
        if (3 == t18.which) {
          e22.hoverData.cxtStarted = true;
          var p11 = { originalEvent: t18, type: "cxttapstart", position: { x: i12[0], y: i12[1] } };
          c10 ? (c10.activate(), c10.emit(p11), e22.hoverData.down = c10) : n14.emit(p11), e22.hoverData.downTime = (/* @__PURE__ */ new Date()).getTime(), e22.hoverData.cxtDragged = false;
        } else if (1 == t18.which) {
          if (c10 && c10.activate(), null != c10 && e22.nodeIsGrabbable(c10)) {
            var g10 = function(e23) {
              return { originalEvent: t18, type: e23, position: { x: i12[0], y: i12[1] } };
            };
            if (s11(c10), c10.selected()) {
              h11 = e22.dragData.possibleDragElements = n14.collection();
              var v13 = n14.$(function(t19) {
                return t19.isNode() && t19.selected() && e22.nodeIsGrabbable(t19);
              });
              u10(v13, { addToList: h11 }), c10.emit(g10("grabon")), v13.forEach(function(e23) {
                e23.emit(g10("grab"));
              });
            } else
              h11 = e22.dragData.possibleDragElements = n14.collection(), d12(c10, { addToList: h11 }), c10.emit(g10("grabon")).emit(g10("grab"));
            e22.redrawHint("eles", true), e22.redrawHint("drag", true);
          }
          e22.hoverData.down = c10, e22.hoverData.downs = l12, e22.hoverData.downTime = (/* @__PURE__ */ new Date()).getTime(), r10(c10, ["mousedown", "tapstart", "vmousedown"], t18, { x: i12[0], y: i12[1] }), null == c10 ? (o14[4] = 1, e22.data.bgActivePosistion = { x: i12[0], y: i12[1] }, e22.redrawHint("select", true), e22.redraw()) : c10.pannable() && (o14[4] = 1), e22.hoverData.tapholdCancelled = false, clearTimeout(e22.hoverData.tapholdTimeout), e22.hoverData.tapholdTimeout = setTimeout(function() {
            if (!e22.hoverData.tapholdCancelled) {
              var r11 = e22.hoverData.down;
              r11 ? r11.emit({ originalEvent: t18, type: "taphold", position: { x: i12[0], y: i12[1] } }) : n14.emit({ originalEvent: t18, type: "taphold", position: { x: i12[0], y: i12[1] } });
            }
          }, e22.tapholdDuration);
        }
        o14[0] = o14[2] = i12[0], o14[1] = o14[3] = i12[1];
      }
    }, false), e22.registerBinding(t17, "mousemove", function(t18) {
      if (e22.hoverData.capture || E10(t18)) {
        var n14 = false, o14 = e22.cy, s12 = o14.zoom(), l12 = [t18.clientX, t18.clientY], c10 = e22.projectIntoViewport(l12[0], l12[1]), d13 = e22.hoverData.mdownPos, p11 = e22.hoverData.mdownGPos, f12 = e22.selection, g10 = null;
        e22.hoverData.draggingEles || e22.hoverData.dragging || e22.hoverData.selecting || (g10 = e22.findNearestElement(c10[0], c10[1], true, false));
        var v13, y11 = e22.hoverData.last, m13 = e22.hoverData.down, b12 = [c10[0] - f12[2], c10[1] - f12[3]], x12 = e22.dragData.possibleDragElements;
        if (p11) {
          var w11 = l12[0] - p11[0], k11 = w11 * w11, C10 = l12[1] - p11[1], S9 = k11 + C10 * C10;
          e22.hoverData.isOverThresholdDrag = v13 = S9 >= e22.desktopTapThreshold2;
        }
        var D8 = a10(t18);
        v13 && (e22.hoverData.tapholdCancelled = true);
        n14 = true, r10(g10, ["mousemove", "vmousemove", "tapdrag"], t18, { x: c10[0], y: c10[1] });
        var P11 = function() {
          e22.data.bgActivePosistion = void 0, e22.hoverData.selecting || o14.emit({ originalEvent: t18, type: "boxstart", position: { x: c10[0], y: c10[1] } }), f12[4] = 1, e22.hoverData.selecting = true, e22.redrawHint("select", true), e22.redraw();
        };
        if (3 === e22.hoverData.which) {
          if (v13) {
            var T10 = { originalEvent: t18, type: "cxtdrag", position: { x: c10[0], y: c10[1] } };
            m13 ? m13.emit(T10) : o14.emit(T10), e22.hoverData.cxtDragged = true, e22.hoverData.cxtOver && g10 === e22.hoverData.cxtOver || (e22.hoverData.cxtOver && e22.hoverData.cxtOver.emit({ originalEvent: t18, type: "cxtdragout", position: { x: c10[0], y: c10[1] } }), e22.hoverData.cxtOver = g10, g10 && g10.emit({ originalEvent: t18, type: "cxtdragover", position: { x: c10[0], y: c10[1] } }));
          }
        } else if (e22.hoverData.dragging) {
          if (n14 = true, o14.panningEnabled() && o14.userPanningEnabled()) {
            var M10;
            if (e22.hoverData.justStartedPan) {
              var B9 = e22.hoverData.mdownPos;
              M10 = { x: (c10[0] - B9[0]) * s12, y: (c10[1] - B9[1]) * s12 }, e22.hoverData.justStartedPan = false;
            } else
              M10 = { x: b12[0] * s12, y: b12[1] * s12 };
            o14.panBy(M10), o14.emit("dragpan"), e22.hoverData.dragged = true;
          }
          c10 = e22.projectIntoViewport(t18.clientX, t18.clientY);
        } else if (1 != f12[4] || null != m13 && !m13.pannable()) {
          if (m13 && m13.pannable() && m13.active() && m13.unactivate(), m13 && m13.grabbed() || g10 == y11 || (y11 && r10(y11, ["mouseout", "tapdragout"], t18, { x: c10[0], y: c10[1] }), g10 && r10(g10, ["mouseover", "tapdragover"], t18, { x: c10[0], y: c10[1] }), e22.hoverData.last = g10), m13)
            if (v13) {
              if (o14.boxSelectionEnabled() && D8)
                m13 && m13.grabbed() && (h10(x12), m13.emit("freeon"), x12.emit("free"), e22.dragData.didDrag && (m13.emit("dragfreeon"), x12.emit("dragfree"))), P11();
              else if (m13 && m13.grabbed() && e22.nodeIsDraggable(m13)) {
                var _8 = !e22.dragData.didDrag;
                _8 && e22.redrawHint("eles", true), e22.dragData.didDrag = true, e22.hoverData.draggingEles || u10(x12, { inDragLayer: true });
                var N9 = { x: 0, y: 0 };
                if (I6(b12[0]) && I6(b12[1]) && (N9.x += b12[0], N9.y += b12[1], _8)) {
                  var z9 = e22.hoverData.dragDelta;
                  z9 && I6(z9[0]) && I6(z9[1]) && (N9.x += z9[0], N9.y += z9[1]);
                }
                e22.hoverData.draggingEles = true, x12.silentShift(N9).emit("position drag"), e22.redrawHint("drag", true), e22.redraw();
              }
            } else
              !function() {
                var t19 = e22.hoverData.dragDelta = e22.hoverData.dragDelta || [];
                0 === t19.length ? (t19.push(b12[0]), t19.push(b12[1])) : (t19[0] += b12[0], t19[1] += b12[1]);
              }();
          n14 = true;
        } else if (v13) {
          if (e22.hoverData.dragging || !o14.boxSelectionEnabled() || !D8 && o14.panningEnabled() && o14.userPanningEnabled()) {
            if (!e22.hoverData.selecting && o14.panningEnabled() && o14.userPanningEnabled()) {
              i11(m13, e22.hoverData.downs) && (e22.hoverData.dragging = true, e22.hoverData.justStartedPan = true, f12[4] = 0, e22.data.bgActivePosistion = ot4(d13), e22.redrawHint("select", true), e22.redraw());
            }
          } else
            P11();
          m13 && m13.pannable() && m13.active() && m13.unactivate();
        }
        return f12[2] = c10[0], f12[3] = c10[1], n14 ? (t18.stopPropagation && t18.stopPropagation(), t18.preventDefault && t18.preventDefault(), false) : void 0;
      }
    }, false), e22.registerBinding(t17, "mouseup", function(t18) {
      if (e22.hoverData.capture) {
        e22.hoverData.capture = false;
        var i12 = e22.cy, o14 = e22.projectIntoViewport(t18.clientX, t18.clientY), s12 = e22.selection, l12 = e22.findNearestElement(o14[0], o14[1], true, false), u11 = e22.dragData.possibleDragElements, c10 = e22.hoverData.down, d13 = a10(t18);
        if (e22.data.bgActivePosistion && (e22.redrawHint("select", true), e22.redraw()), e22.hoverData.tapholdCancelled = true, e22.data.bgActivePosistion = void 0, c10 && c10.unactivate(), 3 === e22.hoverData.which) {
          var p11 = { originalEvent: t18, type: "cxttapend", position: { x: o14[0], y: o14[1] } };
          if (c10 ? c10.emit(p11) : i12.emit(p11), !e22.hoverData.cxtDragged) {
            var f12 = { originalEvent: t18, type: "cxttap", position: { x: o14[0], y: o14[1] } };
            c10 ? c10.emit(f12) : i12.emit(f12);
          }
          e22.hoverData.cxtDragged = false, e22.hoverData.which = null;
        } else if (1 === e22.hoverData.which) {
          if (r10(l12, ["mouseup", "tapend", "vmouseup"], t18, { x: o14[0], y: o14[1] }), e22.dragData.didDrag || e22.hoverData.dragged || e22.hoverData.selecting || e22.hoverData.isOverThresholdDrag || (r10(c10, ["click", "tap", "vclick"], t18, { x: o14[0], y: o14[1] }), x11 = false, t18.timeStamp - w10 <= i12.multiClickDebounceTime() ? (b11 && clearTimeout(b11), x11 = true, w10 = null, r10(c10, ["dblclick", "dbltap", "vdblclick"], t18, { x: o14[0], y: o14[1] })) : (b11 = setTimeout(function() {
            x11 || r10(c10, ["oneclick", "onetap", "voneclick"], t18, { x: o14[0], y: o14[1] });
          }, i12.multiClickDebounceTime()), w10 = t18.timeStamp)), null != c10 || e22.dragData.didDrag || e22.hoverData.selecting || e22.hoverData.dragged || a10(t18) || (i12.$(n13).unselect(["tapunselect"]), u11.length > 0 && e22.redrawHint("eles", true), e22.dragData.possibleDragElements = u11 = i12.collection()), l12 != c10 || e22.dragData.didDrag || e22.hoverData.selecting || null != l12 && l12._private.selectable && (e22.hoverData.dragging || ("additive" === i12.selectionType() || d13 ? l12.selected() ? l12.unselect(["tapunselect"]) : l12.select(["tapselect"]) : d13 || (i12.$(n13).unmerge(l12).unselect(["tapunselect"]), l12.select(["tapselect"]))), e22.redrawHint("eles", true)), e22.hoverData.selecting) {
            var g10 = i12.collection(e22.getAllInBox(s12[0], s12[1], s12[2], s12[3]));
            e22.redrawHint("select", true), g10.length > 0 && e22.redrawHint("eles", true), i12.emit({ type: "boxend", originalEvent: t18, position: { x: o14[0], y: o14[1] } });
            var v13 = function(e23) {
              return e23.selectable() && !e23.selected();
            };
            "additive" === i12.selectionType() || d13 || i12.$(n13).unmerge(g10).unselect(), g10.emit("box").stdFilter(v13).select().emit("boxselect"), e22.redraw();
          }
          if (e22.hoverData.dragging && (e22.hoverData.dragging = false, e22.redrawHint("select", true), e22.redrawHint("eles", true), e22.redraw()), !s12[4]) {
            e22.redrawHint("drag", true), e22.redrawHint("eles", true);
            var y11 = c10 && c10.grabbed();
            h10(u11), y11 && (c10.emit("freeon"), u11.emit("free"), e22.dragData.didDrag && (c10.emit("dragfreeon"), u11.emit("dragfree")));
          }
        }
        s12[4] = 0, e22.hoverData.down = null, e22.hoverData.cxtStarted = false, e22.hoverData.draggingEles = false, e22.hoverData.selecting = false, e22.hoverData.isOverThresholdDrag = false, e22.dragData.didDrag = false, e22.hoverData.dragged = false, e22.hoverData.dragDelta = [], e22.hoverData.mdownPos = null, e22.hoverData.mdownGPos = null;
      }
    }, false);
    var k10, C9, S8, D7, P10, T9, M9, B8, _7, N8, z8, L10, A10, O9 = function(t18) {
      if (!e22.scrollingPage) {
        var n14 = e22.cy, r11 = n14.zoom(), a11 = n14.pan(), i12 = e22.projectIntoViewport(t18.clientX, t18.clientY), o14 = [i12[0] * r11 + a11.x, i12[1] * r11 + a11.y];
        if (e22.hoverData.draggingEles || e22.hoverData.dragging || e22.hoverData.cxtStarted || 0 !== e22.selection[4])
          t18.preventDefault();
        else if (n14.panningEnabled() && n14.userPanningEnabled() && n14.zoomingEnabled() && n14.userZoomingEnabled()) {
          var s12;
          t18.preventDefault(), e22.data.wheelZooming = true, clearTimeout(e22.data.wheelTimeout), e22.data.wheelTimeout = setTimeout(function() {
            e22.data.wheelZooming = false, e22.redrawHint("eles", true), e22.redraw();
          }, 150), s12 = null != t18.deltaY ? t18.deltaY / -250 : null != t18.wheelDeltaY ? t18.wheelDeltaY / 1e3 : t18.wheelDelta / 1e3, s12 *= e22.wheelSensitivity, 1 === t18.deltaMode && (s12 *= 33);
          var l12 = n14.zoom() * Math.pow(10, s12);
          "gesturechange" === t18.type && (l12 = e22.gestureStartZoom * t18.scale), n14.zoom({ level: l12, renderedPosition: { x: o14[0], y: o14[1] } }), n14.emit("gesturechange" === t18.type ? "pinchzoom" : "scrollzoom");
        }
      }
    };
    e22.registerBinding(e22.container, "wheel", O9, true), e22.registerBinding(t17, "scroll", function(t18) {
      e22.scrollingPage = true, clearTimeout(e22.scrollingPageTimeout), e22.scrollingPageTimeout = setTimeout(function() {
        e22.scrollingPage = false;
      }, 250);
    }, true), e22.registerBinding(e22.container, "gesturestart", function(t18) {
      e22.gestureStartZoom = e22.cy.zoom(), e22.hasTouchStarted || t18.preventDefault();
    }, true), e22.registerBinding(e22.container, "gesturechange", function(t18) {
      e22.hasTouchStarted || O9(t18);
    }, true), e22.registerBinding(e22.container, "mouseout", function(t18) {
      var n14 = e22.projectIntoViewport(t18.clientX, t18.clientY);
      e22.cy.emit({ originalEvent: t18, type: "mouseout", position: { x: n14[0], y: n14[1] } });
    }, false), e22.registerBinding(e22.container, "mouseover", function(t18) {
      var n14 = e22.projectIntoViewport(t18.clientX, t18.clientY);
      e22.cy.emit({ originalEvent: t18, type: "mouseover", position: { x: n14[0], y: n14[1] } });
    }, false);
    var R8, V8, F9, q8, j9, Y6, X6, W8 = function(e23, t18, n14, r11) {
      return Math.sqrt((n14 - e23) * (n14 - e23) + (r11 - t18) * (r11 - t18));
    }, H8 = function(e23, t18, n14, r11) {
      return (n14 - e23) * (n14 - e23) + (r11 - t18) * (r11 - t18);
    };
    if (e22.registerBinding(e22.container, "touchstart", R8 = function(t18) {
      if (e22.hasTouchStarted = true, E10(t18)) {
        f11(), e22.touchData.capture = true, e22.data.bgActivePosistion = void 0;
        var n14 = e22.cy, a11 = e22.touchData.now, i12 = e22.touchData.earlier;
        if (t18.touches[0]) {
          var o14 = e22.projectIntoViewport(t18.touches[0].clientX, t18.touches[0].clientY);
          a11[0] = o14[0], a11[1] = o14[1];
        }
        if (t18.touches[1]) {
          o14 = e22.projectIntoViewport(t18.touches[1].clientX, t18.touches[1].clientY);
          a11[2] = o14[0], a11[3] = o14[1];
        }
        if (t18.touches[2]) {
          o14 = e22.projectIntoViewport(t18.touches[2].clientX, t18.touches[2].clientY);
          a11[4] = o14[0], a11[5] = o14[1];
        }
        if (t18.touches[1]) {
          e22.touchData.singleTouchMoved = true, h10(e22.dragData.touchDragEles);
          var l12 = e22.findContainerClientCoords();
          _7 = l12[0], N8 = l12[1], z8 = l12[2], L10 = l12[3], k10 = t18.touches[0].clientX - _7, C9 = t18.touches[0].clientY - N8, S8 = t18.touches[1].clientX - _7, D7 = t18.touches[1].clientY - N8, A10 = 0 <= k10 && k10 <= z8 && 0 <= S8 && S8 <= z8 && 0 <= C9 && C9 <= L10 && 0 <= D7 && D7 <= L10;
          var c10 = n14.pan(), p11 = n14.zoom();
          P10 = W8(k10, C9, S8, D7), T9 = H8(k10, C9, S8, D7), B8 = [((M9 = [(k10 + S8) / 2, (C9 + D7) / 2])[0] - c10.x) / p11, (M9[1] - c10.y) / p11];
          if (T9 < 4e4 && !t18.touches[2]) {
            var g10 = e22.findNearestElement(a11[0], a11[1], true, true), v13 = e22.findNearestElement(a11[2], a11[3], true, true);
            return g10 && g10.isNode() ? (g10.activate().emit({ originalEvent: t18, type: "cxttapstart", position: { x: a11[0], y: a11[1] } }), e22.touchData.start = g10) : v13 && v13.isNode() ? (v13.activate().emit({ originalEvent: t18, type: "cxttapstart", position: { x: a11[0], y: a11[1] } }), e22.touchData.start = v13) : n14.emit({ originalEvent: t18, type: "cxttapstart", position: { x: a11[0], y: a11[1] } }), e22.touchData.start && (e22.touchData.start._private.grabbed = false), e22.touchData.cxt = true, e22.touchData.cxtDragged = false, e22.data.bgActivePosistion = void 0, void e22.redraw();
          }
        }
        if (t18.touches[2])
          n14.boxSelectionEnabled() && t18.preventDefault();
        else if (t18.touches[1])
          ;
        else if (t18.touches[0]) {
          var y11 = e22.findNearestElements(a11[0], a11[1], true, true), m13 = y11[0];
          if (null != m13 && (m13.activate(), e22.touchData.start = m13, e22.touchData.starts = y11, e22.nodeIsGrabbable(m13))) {
            var b12 = e22.dragData.touchDragEles = n14.collection(), x12 = null;
            e22.redrawHint("eles", true), e22.redrawHint("drag", true), m13.selected() ? (x12 = n14.$(function(t19) {
              return t19.selected() && e22.nodeIsGrabbable(t19);
            }), u10(x12, { addToList: b12 })) : d12(m13, { addToList: b12 }), s11(m13);
            var w11 = function(e23) {
              return { originalEvent: t18, type: e23, position: { x: a11[0], y: a11[1] } };
            };
            m13.emit(w11("grabon")), x12 ? x12.forEach(function(e23) {
              e23.emit(w11("grab"));
            }) : m13.emit(w11("grab"));
          }
          r10(m13, ["touchstart", "tapstart", "vmousedown"], t18, { x: a11[0], y: a11[1] }), null == m13 && (e22.data.bgActivePosistion = { x: o14[0], y: o14[1] }, e22.redrawHint("select", true), e22.redraw()), e22.touchData.singleTouchMoved = false, e22.touchData.singleTouchStartTime = +/* @__PURE__ */ new Date(), clearTimeout(e22.touchData.tapholdTimeout), e22.touchData.tapholdTimeout = setTimeout(function() {
            false !== e22.touchData.singleTouchMoved || e22.pinching || e22.touchData.selecting || r10(e22.touchData.start, ["taphold"], t18, { x: a11[0], y: a11[1] });
          }, e22.tapholdDuration);
        }
        if (t18.touches.length >= 1) {
          for (var I8 = e22.touchData.startPosition = [null, null, null, null, null, null], O10 = 0; O10 < a11.length; O10++)
            I8[O10] = i12[O10] = a11[O10];
          var R9 = t18.touches[0];
          e22.touchData.startGPosition = [R9.clientX, R9.clientY];
        }
      }
    }, false), e22.registerBinding(window, "touchmove", V8 = function(t18) {
      var n14 = e22.touchData.capture;
      if (n14 || E10(t18)) {
        var a11 = e22.selection, o14 = e22.cy, s12 = e22.touchData.now, l12 = e22.touchData.earlier, c10 = o14.zoom();
        if (t18.touches[0]) {
          var d13 = e22.projectIntoViewport(t18.touches[0].clientX, t18.touches[0].clientY);
          s12[0] = d13[0], s12[1] = d13[1];
        }
        if (t18.touches[1]) {
          d13 = e22.projectIntoViewport(t18.touches[1].clientX, t18.touches[1].clientY);
          s12[2] = d13[0], s12[3] = d13[1];
        }
        if (t18.touches[2]) {
          d13 = e22.projectIntoViewport(t18.touches[2].clientX, t18.touches[2].clientY);
          s12[4] = d13[0], s12[5] = d13[1];
        }
        var p11, f12 = e22.touchData.startGPosition;
        if (n14 && t18.touches[0] && f12) {
          for (var g10 = [], v13 = 0; v13 < s12.length; v13++)
            g10[v13] = s12[v13] - l12[v13];
          var y11 = t18.touches[0].clientX - f12[0], m13 = y11 * y11, b12 = t18.touches[0].clientY - f12[1];
          p11 = m13 + b12 * b12 >= e22.touchTapThreshold2;
        }
        if (n14 && e22.touchData.cxt) {
          t18.preventDefault();
          var x12 = t18.touches[0].clientX - _7, w11 = t18.touches[0].clientY - N8, M10 = t18.touches[1].clientX - _7, z9 = t18.touches[1].clientY - N8, L11 = H8(x12, w11, M10, z9);
          if (L11 / T9 >= 2.25 || L11 >= 22500) {
            e22.touchData.cxt = false, e22.data.bgActivePosistion = void 0, e22.redrawHint("select", true);
            var O10 = { originalEvent: t18, type: "cxttapend", position: { x: s12[0], y: s12[1] } };
            e22.touchData.start ? (e22.touchData.start.unactivate().emit(O10), e22.touchData.start = null) : o14.emit(O10);
          }
        }
        if (n14 && e22.touchData.cxt) {
          O10 = { originalEvent: t18, type: "cxtdrag", position: { x: s12[0], y: s12[1] } };
          e22.data.bgActivePosistion = void 0, e22.redrawHint("select", true), e22.touchData.start ? e22.touchData.start.emit(O10) : o14.emit(O10), e22.touchData.start && (e22.touchData.start._private.grabbed = false), e22.touchData.cxtDragged = true;
          var R9 = e22.findNearestElement(s12[0], s12[1], true, true);
          e22.touchData.cxtOver && R9 === e22.touchData.cxtOver || (e22.touchData.cxtOver && e22.touchData.cxtOver.emit({ originalEvent: t18, type: "cxtdragout", position: { x: s12[0], y: s12[1] } }), e22.touchData.cxtOver = R9, R9 && R9.emit({ originalEvent: t18, type: "cxtdragover", position: { x: s12[0], y: s12[1] } }));
        } else if (n14 && t18.touches[2] && o14.boxSelectionEnabled())
          t18.preventDefault(), e22.data.bgActivePosistion = void 0, this.lastThreeTouch = +/* @__PURE__ */ new Date(), e22.touchData.selecting || o14.emit({ originalEvent: t18, type: "boxstart", position: { x: s12[0], y: s12[1] } }), e22.touchData.selecting = true, e22.touchData.didSelect = true, a11[4] = 1, a11 && 0 !== a11.length && void 0 !== a11[0] ? (a11[2] = (s12[0] + s12[2] + s12[4]) / 3, a11[3] = (s12[1] + s12[3] + s12[5]) / 3) : (a11[0] = (s12[0] + s12[2] + s12[4]) / 3, a11[1] = (s12[1] + s12[3] + s12[5]) / 3, a11[2] = (s12[0] + s12[2] + s12[4]) / 3 + 1, a11[3] = (s12[1] + s12[3] + s12[5]) / 3 + 1), e22.redrawHint("select", true), e22.redraw();
        else if (n14 && t18.touches[1] && !e22.touchData.didSelect && o14.zoomingEnabled() && o14.panningEnabled() && o14.userZoomingEnabled() && o14.userPanningEnabled()) {
          if (t18.preventDefault(), e22.data.bgActivePosistion = void 0, e22.redrawHint("select", true), ee3 = e22.dragData.touchDragEles) {
            e22.redrawHint("drag", true);
            for (var V9 = 0; V9 < ee3.length; V9++) {
              var F10 = ee3[V9]._private;
              F10.grabbed = false, F10.rscratch.inDragLayer = false;
            }
          }
          var q9 = e22.touchData.start, j10 = (x12 = t18.touches[0].clientX - _7, w11 = t18.touches[0].clientY - N8, M10 = t18.touches[1].clientX - _7, z9 = t18.touches[1].clientY - N8, W8(x12, w11, M10, z9)), Y7 = j10 / P10;
          if (A10) {
            var X7 = (x12 - k10 + (M10 - S8)) / 2, K7 = (w11 - C9 + (z9 - D7)) / 2, G7 = o14.zoom(), U8 = G7 * Y7, Z7 = o14.pan(), $9 = B8[0] * G7 + Z7.x, Q7 = B8[1] * G7 + Z7.y, J6 = { x: -U8 / G7 * ($9 - Z7.x - X7) + $9, y: -U8 / G7 * (Q7 - Z7.y - K7) + Q7 };
            if (q9 && q9.active()) {
              var ee3 = e22.dragData.touchDragEles;
              h10(ee3), e22.redrawHint("drag", true), e22.redrawHint("eles", true), q9.unactivate().emit("freeon"), ee3.emit("free"), e22.dragData.didDrag && (q9.emit("dragfreeon"), ee3.emit("dragfree"));
            }
            o14.viewport({ zoom: U8, pan: J6, cancelOnFailedZoom: true }), o14.emit("pinchzoom"), P10 = j10, k10 = x12, C9 = w11, S8 = M10, D7 = z9, e22.pinching = true;
          }
          if (t18.touches[0]) {
            d13 = e22.projectIntoViewport(t18.touches[0].clientX, t18.touches[0].clientY);
            s12[0] = d13[0], s12[1] = d13[1];
          }
          if (t18.touches[1]) {
            d13 = e22.projectIntoViewport(t18.touches[1].clientX, t18.touches[1].clientY);
            s12[2] = d13[0], s12[3] = d13[1];
          }
          if (t18.touches[2]) {
            d13 = e22.projectIntoViewport(t18.touches[2].clientX, t18.touches[2].clientY);
            s12[4] = d13[0], s12[5] = d13[1];
          }
        } else if (t18.touches[0] && !e22.touchData.didSelect) {
          var te3 = e22.touchData.start, ne3 = e22.touchData.last;
          if (e22.hoverData.draggingEles || e22.swipePanning || (R9 = e22.findNearestElement(s12[0], s12[1], true, true)), n14 && null != te3 && t18.preventDefault(), n14 && null != te3 && e22.nodeIsDraggable(te3))
            if (p11) {
              ee3 = e22.dragData.touchDragEles;
              var re3 = !e22.dragData.didDrag;
              re3 && u10(ee3, { inDragLayer: true }), e22.dragData.didDrag = true;
              var ae3 = { x: 0, y: 0 };
              if (I6(g10[0]) && I6(g10[1])) {
                if (ae3.x += g10[0], ae3.y += g10[1], re3)
                  e22.redrawHint("eles", true), (ie3 = e22.touchData.dragDelta) && I6(ie3[0]) && I6(ie3[1]) && (ae3.x += ie3[0], ae3.y += ie3[1]);
              }
              e22.hoverData.draggingEles = true, ee3.silentShift(ae3).emit("position drag"), e22.redrawHint("drag", true), e22.touchData.startPosition[0] == l12[0] && e22.touchData.startPosition[1] == l12[1] && e22.redrawHint("eles", true), e22.redraw();
            } else {
              var ie3;
              0 === (ie3 = e22.touchData.dragDelta = e22.touchData.dragDelta || []).length ? (ie3.push(g10[0]), ie3.push(g10[1])) : (ie3[0] += g10[0], ie3[1] += g10[1]);
            }
          if (r10(te3 || R9, ["touchmove", "tapdrag", "vmousemove"], t18, { x: s12[0], y: s12[1] }), te3 && te3.grabbed() || R9 == ne3 || (ne3 && ne3.emit({ originalEvent: t18, type: "tapdragout", position: { x: s12[0], y: s12[1] } }), R9 && R9.emit({ originalEvent: t18, type: "tapdragover", position: { x: s12[0], y: s12[1] } })), e22.touchData.last = R9, n14)
            for (V9 = 0; V9 < s12.length; V9++)
              s12[V9] && e22.touchData.startPosition[V9] && p11 && (e22.touchData.singleTouchMoved = true);
          if (n14 && (null == te3 || te3.pannable()) && o14.panningEnabled() && o14.userPanningEnabled()) {
            i11(te3, e22.touchData.starts) && (t18.preventDefault(), e22.data.bgActivePosistion || (e22.data.bgActivePosistion = ot4(e22.touchData.startPosition)), e22.swipePanning ? (o14.panBy({ x: g10[0] * c10, y: g10[1] * c10 }), o14.emit("dragpan")) : p11 && (e22.swipePanning = true, o14.panBy({ x: y11 * c10, y: b12 * c10 }), o14.emit("dragpan"), te3 && (te3.unactivate(), e22.redrawHint("select", true), e22.touchData.start = null)));
            d13 = e22.projectIntoViewport(t18.touches[0].clientX, t18.touches[0].clientY);
            s12[0] = d13[0], s12[1] = d13[1];
          }
        }
        for (v13 = 0; v13 < s12.length; v13++)
          l12[v13] = s12[v13];
        n14 && t18.touches.length > 0 && !e22.hoverData.draggingEles && !e22.swipePanning && null != e22.data.bgActivePosistion && (e22.data.bgActivePosistion = void 0, e22.redrawHint("select", true), e22.redraw());
      }
    }, false), e22.registerBinding(t17, "touchcancel", F9 = function(t18) {
      var n14 = e22.touchData.start;
      e22.touchData.capture = false, n14 && n14.unactivate();
    }), e22.registerBinding(t17, "touchend", q8 = function(t18) {
      var a11 = e22.touchData.start;
      if (e22.touchData.capture) {
        0 === t18.touches.length && (e22.touchData.capture = false), t18.preventDefault();
        var i12 = e22.selection;
        e22.swipePanning = false, e22.hoverData.draggingEles = false;
        var o14, s12 = e22.cy, l12 = s12.zoom(), u11 = e22.touchData.now, c10 = e22.touchData.earlier;
        if (t18.touches[0]) {
          var d13 = e22.projectIntoViewport(t18.touches[0].clientX, t18.touches[0].clientY);
          u11[0] = d13[0], u11[1] = d13[1];
        }
        if (t18.touches[1]) {
          d13 = e22.projectIntoViewport(t18.touches[1].clientX, t18.touches[1].clientY);
          u11[2] = d13[0], u11[3] = d13[1];
        }
        if (t18.touches[2]) {
          d13 = e22.projectIntoViewport(t18.touches[2].clientX, t18.touches[2].clientY);
          u11[4] = d13[0], u11[5] = d13[1];
        }
        if (a11 && a11.unactivate(), e22.touchData.cxt) {
          if (o14 = { originalEvent: t18, type: "cxttapend", position: { x: u11[0], y: u11[1] } }, a11 ? a11.emit(o14) : s12.emit(o14), !e22.touchData.cxtDragged) {
            var p11 = { originalEvent: t18, type: "cxttap", position: { x: u11[0], y: u11[1] } };
            a11 ? a11.emit(p11) : s12.emit(p11);
          }
          return e22.touchData.start && (e22.touchData.start._private.grabbed = false), e22.touchData.cxt = false, e22.touchData.start = null, void e22.redraw();
        }
        if (!t18.touches[2] && s12.boxSelectionEnabled() && e22.touchData.selecting) {
          e22.touchData.selecting = false;
          var f12 = s12.collection(e22.getAllInBox(i12[0], i12[1], i12[2], i12[3]));
          i12[0] = void 0, i12[1] = void 0, i12[2] = void 0, i12[3] = void 0, i12[4] = 0, e22.redrawHint("select", true), s12.emit({ type: "boxend", originalEvent: t18, position: { x: u11[0], y: u11[1] } });
          f12.emit("box").stdFilter(function(e23) {
            return e23.selectable() && !e23.selected();
          }).select().emit("boxselect"), f12.nonempty() && e22.redrawHint("eles", true), e22.redraw();
        }
        if (null != a11 && a11.unactivate(), t18.touches[2])
          e22.data.bgActivePosistion = void 0, e22.redrawHint("select", true);
        else if (t18.touches[1])
          ;
        else if (t18.touches[0])
          ;
        else if (!t18.touches[0]) {
          e22.data.bgActivePosistion = void 0, e22.redrawHint("select", true);
          var g10 = e22.dragData.touchDragEles;
          if (null != a11) {
            var v13 = a11._private.grabbed;
            h10(g10), e22.redrawHint("drag", true), e22.redrawHint("eles", true), v13 && (a11.emit("freeon"), g10.emit("free"), e22.dragData.didDrag && (a11.emit("dragfreeon"), g10.emit("dragfree"))), r10(a11, ["touchend", "tapend", "vmouseup", "tapdragout"], t18, { x: u11[0], y: u11[1] }), a11.unactivate(), e22.touchData.start = null;
          } else {
            var y11 = e22.findNearestElement(u11[0], u11[1], true, true);
            r10(y11, ["touchend", "tapend", "vmouseup", "tapdragout"], t18, { x: u11[0], y: u11[1] });
          }
          var m13 = e22.touchData.startPosition[0] - u11[0], b12 = m13 * m13, x12 = e22.touchData.startPosition[1] - u11[1], w11 = (b12 + x12 * x12) * l12 * l12;
          e22.touchData.singleTouchMoved || (a11 || s12.$(":selected").unselect(["tapunselect"]), r10(a11, ["tap", "vclick"], t18, { x: u11[0], y: u11[1] }), j9 = false, t18.timeStamp - X6 <= s12.multiClickDebounceTime() ? (Y6 && clearTimeout(Y6), j9 = true, X6 = null, r10(a11, ["dbltap", "vdblclick"], t18, { x: u11[0], y: u11[1] })) : (Y6 = setTimeout(function() {
            j9 || r10(a11, ["onetap", "voneclick"], t18, { x: u11[0], y: u11[1] });
          }, s12.multiClickDebounceTime()), X6 = t18.timeStamp)), null != a11 && !e22.dragData.didDrag && a11._private.selectable && w11 < e22.touchTapThreshold2 && !e22.pinching && ("single" === s12.selectionType() ? (s12.$(n13).unmerge(a11).unselect(["tapunselect"]), a11.select(["tapselect"])) : a11.selected() ? a11.unselect(["tapunselect"]) : a11.select(["tapselect"]), e22.redrawHint("eles", true)), e22.touchData.singleTouchMoved = true;
        }
        for (var E11 = 0; E11 < u11.length; E11++)
          c10[E11] = u11[E11];
        e22.dragData.didDrag = false, 0 === t18.touches.length && (e22.touchData.dragDelta = [], e22.touchData.startPosition = [null, null, null, null, null, null], e22.touchData.startGPosition = null, e22.touchData.didSelect = false), t18.touches.length < 2 && (1 === t18.touches.length && (e22.touchData.startGPosition = [t18.touches[0].clientX, t18.touches[0].clientY]), e22.pinching = false, e22.redrawHint("eles", true), e22.redraw());
      }
    }, false), "undefined" == typeof TouchEvent) {
      var K6 = [], G6 = function(e23) {
        return { clientX: e23.clientX, clientY: e23.clientY, force: 1, identifier: e23.pointerId, pageX: e23.pageX, pageY: e23.pageY, radiusX: e23.width / 2, radiusY: e23.height / 2, screenX: e23.screenX, screenY: e23.screenY, target: e23.target };
      }, U7 = function(e23) {
        K6.push(function(e24) {
          return { event: e24, touch: G6(e24) };
        }(e23));
      }, Z6 = function(e23) {
        for (var t18 = 0; t18 < K6.length; t18++) {
          if (K6[t18].event.pointerId === e23.pointerId)
            return void K6.splice(t18, 1);
        }
      }, $8 = function(e23) {
        e23.touches = K6.map(function(e24) {
          return e24.touch;
        });
      }, Q6 = function(e23) {
        return "mouse" === e23.pointerType || 4 === e23.pointerType;
      };
      e22.registerBinding(e22.container, "pointerdown", function(e23) {
        Q6(e23) || (e23.preventDefault(), U7(e23), $8(e23), R8(e23));
      }), e22.registerBinding(e22.container, "pointerup", function(e23) {
        Q6(e23) || (Z6(e23), $8(e23), q8(e23));
      }), e22.registerBinding(e22.container, "pointercancel", function(e23) {
        Q6(e23) || (Z6(e23), $8(e23), F9());
      }), e22.registerBinding(e22.container, "pointermove", function(e23) {
        Q6(e23) || (e23.preventDefault(), function(e24) {
          var t18 = K6.filter(function(t19) {
            return t19.event.pointerId === e24.pointerId;
          })[0];
          t18.event = e24, t18.touch = G6(e24);
        }(e23), $8(e23), V8(e23));
      });
    }
  };
  var ms = { generatePolygon: function(e22, t17) {
    return this.nodeShapes[e22] = { renderer: this, name: e22, points: t17, draw: function(e23, t18, n13, r10, a10) {
      this.renderer.nodeShapeImpl("polygon", e23, t18, n13, r10, a10, this.points);
    }, intersectLine: function(e23, t18, n13, r10, a10, i11, o13) {
      return Ot4(a10, i11, this.points, e23, t18, n13 / 2, r10 / 2, o13);
    }, checkPoint: function(e23, t18, n13, r10, a10, i11, o13) {
      return Bt4(e23, t18, this.points, i11, o13, r10, a10, [0, -1], n13);
    } };
  } };
  ms.generateEllipse = function() {
    return this.nodeShapes.ellipse = { renderer: this, name: "ellipse", draw: function(e22, t17, n13, r10, a10) {
      this.renderer.nodeShapeImpl(this.name, e22, t17, n13, r10, a10);
    }, intersectLine: function(e22, t17, n13, r10, a10, i11, o13) {
      return function(e23, t18, n14, r11, a11, i12) {
        var o14 = n14 - e23, s11 = r11 - t18;
        o14 /= a11, s11 /= i12;
        var l11 = Math.sqrt(o14 * o14 + s11 * s11), u10 = l11 - 1;
        if (u10 < 0)
          return [];
        var c10 = u10 / l11;
        return [(n14 - e23) * c10 + e23, (r11 - t18) * c10 + t18];
      }(a10, i11, e22, t17, n13 / 2 + o13, r10 / 2 + o13);
    }, checkPoint: function(e22, t17, n13, r10, a10, i11, o13) {
      return It4(e22, t17, r10, a10, i11, o13, n13);
    } };
  }, ms.generateRoundPolygon = function(e22, t17) {
    for (var n13 = new Array(2 * t17.length), r10 = 0; r10 < t17.length / 2; r10++) {
      var a10 = 2 * r10, i11 = void 0;
      i11 = r10 < t17.length / 2 - 1 ? 2 * (r10 + 1) : 0, n13[4 * r10] = t17[a10], n13[4 * r10 + 1] = t17[a10 + 1];
      var o13 = t17[i11] - t17[a10], s11 = t17[i11 + 1] - t17[a10 + 1], l11 = Math.sqrt(o13 * o13 + s11 * s11);
      n13[4 * r10 + 2] = o13 / l11, n13[4 * r10 + 3] = s11 / l11;
    }
    return this.nodeShapes[e22] = { renderer: this, name: e22, points: n13, draw: function(e23, t18, n14, r11, a11) {
      this.renderer.nodeShapeImpl("round-polygon", e23, t18, n14, r11, a11, this.points);
    }, intersectLine: function(e23, t18, n14, r11, a11, i12, o14) {
      return function(e24, t19, n15, r12, a12, i13, o15, s12) {
        for (var l12, u10 = [], c10 = new Array(n15.length), d12 = i13 / 2, h10 = o15 / 2, p10 = Yt4(i13, o15), f11 = 0; f11 < n15.length / 4; f11++) {
          var g9, v12 = void 0;
          v12 = 0 === f11 ? n15.length - 2 : 4 * f11 - 2, g9 = 4 * f11 + 2;
          var y10 = r12 + d12 * n15[4 * f11], m12 = a12 + h10 * n15[4 * f11 + 1], b11 = -n15[v12] * n15[g9] - n15[v12 + 1] * n15[g9 + 1], x11 = p10 / Math.tan(Math.acos(b11) / 2), w10 = y10 - x11 * n15[v12], E10 = m12 - x11 * n15[v12 + 1], k10 = y10 + x11 * n15[g9], C9 = m12 + x11 * n15[g9 + 1];
          0 === f11 ? (c10[n15.length - 2] = w10, c10[n15.length - 1] = E10) : (c10[4 * f11 - 2] = w10, c10[4 * f11 - 1] = E10), c10[4 * f11] = k10, c10[4 * f11 + 1] = C9;
          var S8 = n15[v12 + 1], D7 = -n15[v12];
          S8 * n15[g9] + D7 * n15[g9 + 1] < 0 && (S8 *= -1, D7 *= -1), 0 !== (l12 = zt4(e24, t19, r12, a12, w10 + S8 * p10, E10 + D7 * p10, p10)).length && u10.push(l12[0], l12[1]);
        }
        for (var P10 = 0; P10 < c10.length / 4; P10++)
          0 !== (l12 = At4(e24, t19, r12, a12, c10[4 * P10], c10[4 * P10 + 1], c10[4 * P10 + 2], c10[4 * P10 + 3], false)).length && u10.push(l12[0], l12[1]);
        if (u10.length > 2) {
          for (var T9 = [u10[0], u10[1]], M9 = Math.pow(T9[0] - e24, 2) + Math.pow(T9[1] - t19, 2), B8 = 1; B8 < u10.length / 2; B8++) {
            var _7 = Math.pow(u10[2 * B8] - e24, 2) + Math.pow(u10[2 * B8 + 1] - t19, 2);
            _7 <= M9 && (T9[0] = u10[2 * B8], T9[1] = u10[2 * B8 + 1], M9 = _7);
          }
          return T9;
        }
        return u10;
      }(a11, i12, this.points, e23, t18, n14, r11);
    }, checkPoint: function(e23, t18, n14, r11, a11, i12, o14) {
      return function(e24, t19, n15, r12, a12, i13, o15) {
        for (var s12 = new Array(n15.length), l12 = i13 / 2, u10 = o15 / 2, c10 = Yt4(i13, o15), d12 = c10 * c10, h10 = 0; h10 < n15.length / 4; h10++) {
          var p10, f11 = void 0;
          f11 = 0 === h10 ? n15.length - 2 : 4 * h10 - 2, p10 = 4 * h10 + 2;
          var g9 = r12 + l12 * n15[4 * h10], v12 = a12 + u10 * n15[4 * h10 + 1], y10 = -n15[f11] * n15[p10] - n15[f11 + 1] * n15[p10 + 1], m12 = c10 / Math.tan(Math.acos(y10) / 2), b11 = g9 - m12 * n15[f11], x11 = v12 - m12 * n15[f11 + 1], w10 = g9 + m12 * n15[p10], E10 = v12 + m12 * n15[p10 + 1];
          s12[4 * h10] = b11, s12[4 * h10 + 1] = x11, s12[4 * h10 + 2] = w10, s12[4 * h10 + 3] = E10;
          var k10 = n15[f11 + 1], C9 = -n15[f11];
          k10 * n15[p10] + C9 * n15[p10 + 1] < 0 && (k10 *= -1, C9 *= -1);
          var S8 = b11 + k10 * c10, D7 = x11 + C9 * c10;
          if (Math.pow(S8 - e24, 2) + Math.pow(D7 - t19, 2) <= d12)
            return true;
        }
        return Mt4(e24, t19, s12);
      }(e23, t18, this.points, i12, o14, r11, a11);
    } };
  }, ms.generateRoundRectangle = function() {
    return this.nodeShapes["round-rectangle"] = this.nodeShapes.roundrectangle = { renderer: this, name: "round-rectangle", points: Vt4(4, 0), draw: function(e22, t17, n13, r10, a10) {
      this.renderer.nodeShapeImpl(this.name, e22, t17, n13, r10, a10);
    }, intersectLine: function(e22, t17, n13, r10, a10, i11, o13) {
      return Ct4(a10, i11, e22, t17, n13, r10, o13);
    }, checkPoint: function(e22, t17, n13, r10, a10, i11, o13) {
      var s11 = jt4(r10, a10), l11 = 2 * s11;
      return !!Bt4(e22, t17, this.points, i11, o13, r10, a10 - l11, [0, -1], n13) || (!!Bt4(e22, t17, this.points, i11, o13, r10 - l11, a10, [0, -1], n13) || (!!It4(e22, t17, l11, l11, i11 - r10 / 2 + s11, o13 - a10 / 2 + s11, n13) || (!!It4(e22, t17, l11, l11, i11 + r10 / 2 - s11, o13 - a10 / 2 + s11, n13) || (!!It4(e22, t17, l11, l11, i11 + r10 / 2 - s11, o13 + a10 / 2 - s11, n13) || !!It4(e22, t17, l11, l11, i11 - r10 / 2 + s11, o13 + a10 / 2 - s11, n13)))));
    } };
  }, ms.generateCutRectangle = function() {
    return this.nodeShapes["cut-rectangle"] = this.nodeShapes.cutrectangle = { renderer: this, name: "cut-rectangle", cornerLength: 8, points: Vt4(4, 0), draw: function(e22, t17, n13, r10, a10) {
      this.renderer.nodeShapeImpl(this.name, e22, t17, n13, r10, a10);
    }, generateCutTrianglePts: function(e22, t17, n13, r10) {
      var a10 = this.cornerLength, i11 = t17 / 2, o13 = e22 / 2, s11 = n13 - o13, l11 = n13 + o13, u10 = r10 - i11, c10 = r10 + i11;
      return { topLeft: [s11, u10 + a10, s11 + a10, u10, s11 + a10, u10 + a10], topRight: [l11 - a10, u10, l11, u10 + a10, l11 - a10, u10 + a10], bottomRight: [l11, c10 - a10, l11 - a10, c10, l11 - a10, c10 - a10], bottomLeft: [s11 + a10, c10, s11, c10 - a10, s11 + a10, c10 - a10] };
    }, intersectLine: function(e22, t17, n13, r10, a10, i11, o13) {
      var s11 = this.generateCutTrianglePts(n13 + 2 * o13, r10 + 2 * o13, e22, t17), l11 = [].concat.apply([], [s11.topLeft.splice(0, 4), s11.topRight.splice(0, 4), s11.bottomRight.splice(0, 4), s11.bottomLeft.splice(0, 4)]);
      return Ot4(a10, i11, l11, e22, t17);
    }, checkPoint: function(e22, t17, n13, r10, a10, i11, o13) {
      if (Bt4(e22, t17, this.points, i11, o13, r10, a10 - 2 * this.cornerLength, [0, -1], n13))
        return true;
      if (Bt4(e22, t17, this.points, i11, o13, r10 - 2 * this.cornerLength, a10, [0, -1], n13))
        return true;
      var s11 = this.generateCutTrianglePts(r10, a10, i11, o13);
      return Mt4(e22, t17, s11.topLeft) || Mt4(e22, t17, s11.topRight) || Mt4(e22, t17, s11.bottomRight) || Mt4(e22, t17, s11.bottomLeft);
    } };
  }, ms.generateBarrel = function() {
    return this.nodeShapes.barrel = { renderer: this, name: "barrel", points: Vt4(4, 0), draw: function(e22, t17, n13, r10, a10) {
      this.renderer.nodeShapeImpl(this.name, e22, t17, n13, r10, a10);
    }, intersectLine: function(e22, t17, n13, r10, a10, i11, o13) {
      var s11 = this.generateBarrelBezierPts(n13 + 2 * o13, r10 + 2 * o13, e22, t17), l11 = function(e23) {
        var t18 = ft4({ x: e23[0], y: e23[1] }, { x: e23[2], y: e23[3] }, { x: e23[4], y: e23[5] }, 0.15), n14 = ft4({ x: e23[0], y: e23[1] }, { x: e23[2], y: e23[3] }, { x: e23[4], y: e23[5] }, 0.5), r11 = ft4({ x: e23[0], y: e23[1] }, { x: e23[2], y: e23[3] }, { x: e23[4], y: e23[5] }, 0.85);
        return [e23[0], e23[1], t18.x, t18.y, n14.x, n14.y, r11.x, r11.y, e23[4], e23[5]];
      }, u10 = [].concat(l11(s11.topLeft), l11(s11.topRight), l11(s11.bottomRight), l11(s11.bottomLeft));
      return Ot4(a10, i11, u10, e22, t17);
    }, generateBarrelBezierPts: function(e22, t17, n13, r10) {
      var a10 = t17 / 2, i11 = e22 / 2, o13 = n13 - i11, s11 = n13 + i11, l11 = r10 - a10, u10 = r10 + a10, c10 = Xt4(e22, t17), d12 = c10.heightOffset, h10 = c10.widthOffset, p10 = c10.ctrlPtOffsetPct * e22, f11 = { topLeft: [o13, l11 + d12, o13 + p10, l11, o13 + h10, l11], topRight: [s11 - h10, l11, s11 - p10, l11, s11, l11 + d12], bottomRight: [s11, u10 - d12, s11 - p10, u10, s11 - h10, u10], bottomLeft: [o13 + h10, u10, o13 + p10, u10, o13, u10 - d12] };
      return f11.topLeft.isTop = true, f11.topRight.isTop = true, f11.bottomLeft.isBottom = true, f11.bottomRight.isBottom = true, f11;
    }, checkPoint: function(e22, t17, n13, r10, a10, i11, o13) {
      var s11 = Xt4(r10, a10), l11 = s11.heightOffset, u10 = s11.widthOffset;
      if (Bt4(e22, t17, this.points, i11, o13, r10, a10 - 2 * l11, [0, -1], n13))
        return true;
      if (Bt4(e22, t17, this.points, i11, o13, r10 - 2 * u10, a10, [0, -1], n13))
        return true;
      for (var c10 = this.generateBarrelBezierPts(r10, a10, i11, o13), d12 = function(e23, t18, n14) {
        var r11, a11, i12 = n14[4], o14 = n14[2], s12 = n14[0], l12 = n14[5], u11 = n14[1], c11 = Math.min(i12, s12), d13 = Math.max(i12, s12), h11 = Math.min(l12, u11), p11 = Math.max(l12, u11);
        if (c11 <= e23 && e23 <= d13 && h11 <= t18 && t18 <= p11) {
          var f12 = [(r11 = i12) - 2 * (a11 = o14) + s12, 2 * (a11 - r11), r11], g10 = function(e24, t19, n15, r12) {
            var a12 = t19 * t19 - 4 * e24 * (n15 -= r12);
            if (a12 < 0)
              return [];
            var i13 = Math.sqrt(a12), o15 = 2 * e24;
            return [(-t19 + i13) / o15, (-t19 - i13) / o15];
          }(f12[0], f12[1], f12[2], e23).filter(function(e24) {
            return 0 <= e24 && e24 <= 1;
          });
          if (g10.length > 0)
            return g10[0];
        }
        return null;
      }, h10 = Object.keys(c10), p10 = 0; p10 < h10.length; p10++) {
        var f11 = c10[h10[p10]], g9 = d12(e22, t17, f11);
        if (null != g9) {
          var v12 = f11[5], y10 = f11[3], m12 = f11[1], b11 = pt4(v12, y10, m12, g9);
          if (f11.isTop && b11 <= t17)
            return true;
          if (f11.isBottom && t17 <= b11)
            return true;
        }
      }
      return false;
    } };
  }, ms.generateBottomRoundrectangle = function() {
    return this.nodeShapes["bottom-round-rectangle"] = this.nodeShapes.bottomroundrectangle = { renderer: this, name: "bottom-round-rectangle", points: Vt4(4, 0), draw: function(e22, t17, n13, r10, a10) {
      this.renderer.nodeShapeImpl(this.name, e22, t17, n13, r10, a10);
    }, intersectLine: function(e22, t17, n13, r10, a10, i11, o13) {
      var s11 = t17 - (r10 / 2 + o13), l11 = At4(a10, i11, e22, t17, e22 - (n13 / 2 + o13), s11, e22 + (n13 / 2 + o13), s11, false);
      return l11.length > 0 ? l11 : Ct4(a10, i11, e22, t17, n13, r10, o13);
    }, checkPoint: function(e22, t17, n13, r10, a10, i11, o13) {
      var s11 = jt4(r10, a10), l11 = 2 * s11;
      if (Bt4(e22, t17, this.points, i11, o13, r10, a10 - l11, [0, -1], n13))
        return true;
      if (Bt4(e22, t17, this.points, i11, o13, r10 - l11, a10, [0, -1], n13))
        return true;
      var u10 = r10 / 2 + 2 * n13, c10 = a10 / 2 + 2 * n13;
      return !!Mt4(e22, t17, [i11 - u10, o13 - c10, i11 - u10, o13, i11 + u10, o13, i11 + u10, o13 - c10]) || (!!It4(e22, t17, l11, l11, i11 + r10 / 2 - s11, o13 + a10 / 2 - s11, n13) || !!It4(e22, t17, l11, l11, i11 - r10 / 2 + s11, o13 + a10 / 2 - s11, n13));
    } };
  }, ms.registerNodeShapes = function() {
    var e22 = this.nodeShapes = {}, t17 = this;
    this.generateEllipse(), this.generatePolygon("triangle", Vt4(3, 0)), this.generateRoundPolygon("round-triangle", Vt4(3, 0)), this.generatePolygon("rectangle", Vt4(4, 0)), e22.square = e22.rectangle, this.generateRoundRectangle(), this.generateCutRectangle(), this.generateBarrel(), this.generateBottomRoundrectangle();
    var n13 = [0, 1, 1, 0, 0, -1, -1, 0];
    this.generatePolygon("diamond", n13), this.generateRoundPolygon("round-diamond", n13), this.generatePolygon("pentagon", Vt4(5, 0)), this.generateRoundPolygon("round-pentagon", Vt4(5, 0)), this.generatePolygon("hexagon", Vt4(6, 0)), this.generateRoundPolygon("round-hexagon", Vt4(6, 0)), this.generatePolygon("heptagon", Vt4(7, 0)), this.generateRoundPolygon("round-heptagon", Vt4(7, 0)), this.generatePolygon("octagon", Vt4(8, 0)), this.generateRoundPolygon("round-octagon", Vt4(8, 0));
    var r10 = new Array(20), a10 = qt4(5, 0), i11 = qt4(5, Math.PI / 5), o13 = 0.5 * (3 - Math.sqrt(5));
    o13 *= 1.57;
    for (var s11 = 0; s11 < i11.length / 2; s11++)
      i11[2 * s11] *= o13, i11[2 * s11 + 1] *= o13;
    for (s11 = 0; s11 < 5; s11++)
      r10[4 * s11] = a10[2 * s11], r10[4 * s11 + 1] = a10[2 * s11 + 1], r10[4 * s11 + 2] = i11[2 * s11], r10[4 * s11 + 3] = i11[2 * s11 + 1];
    r10 = Ft4(r10), this.generatePolygon("star", r10), this.generatePolygon("vee", [-1, -1, 0, -0.333, 1, -1, 0, 1]), this.generatePolygon("rhomboid", [-1, -1, 0.333, -1, 1, 1, -0.333, 1]), this.generatePolygon("right-rhomboid", [-0.333, -1, 1, -1, 0.333, 1, -1, 1]), this.nodeShapes.concavehexagon = this.generatePolygon("concave-hexagon", [-1, -0.95, -0.75, 0, -1, 0.95, 1, 0.95, 0.75, 0, 1, -0.95]);
    var l11 = [-1, -1, 0.25, -1, 1, 0, 0.25, 1, -1, 1];
    this.generatePolygon("tag", l11), this.generateRoundPolygon("round-tag", l11), e22.makePolygon = function(e23) {
      var n14, r11 = "polygon-" + e23.join("$");
      return (n14 = this[r11]) ? n14 : t17.generatePolygon(r11, e23);
    };
  };
  var bs = { timeToRender: function() {
    return this.redrawTotalTime / this.redrawCount;
  }, redraw: function(e22) {
    e22 = e22 || Ie();
    var t17 = this;
    void 0 === t17.averageRedrawTime && (t17.averageRedrawTime = 0), void 0 === t17.lastRedrawTime && (t17.lastRedrawTime = 0), void 0 === t17.lastDrawTime && (t17.lastDrawTime = 0), t17.requestedFrame = true, t17.renderOptions = e22;
  }, beforeRender: function(e22, t17) {
    if (!this.destroyed) {
      null == t17 && Pe("Priority is not optional for beforeRender");
      var n13 = this.beforeRenderCallbacks;
      n13.push({ fn: e22, priority: t17 }), n13.sort(function(e23, t18) {
        return t18.priority - e23.priority;
      });
    }
  } };
  var xs = function(e22, t17, n13) {
    for (var r10 = e22.beforeRenderCallbacks, a10 = 0; a10 < r10.length; a10++)
      r10[a10].fn(t17, n13);
  };
  bs.startRenderLoop = function() {
    var e22 = this, t17 = e22.cy;
    if (!e22.renderLoopStarted) {
      e22.renderLoopStarted = true;
      se(function n13(r10) {
        if (!e22.destroyed) {
          if (t17.batching())
            ;
          else if (e22.requestedFrame && !e22.skipFrame) {
            xs(e22, true, r10);
            var a10 = le();
            e22.render(e22.renderOptions);
            var i11 = e22.lastDrawTime = le();
            void 0 === e22.averageRedrawTime && (e22.averageRedrawTime = i11 - a10), void 0 === e22.redrawCount && (e22.redrawCount = 0), e22.redrawCount++, void 0 === e22.redrawTotalTime && (e22.redrawTotalTime = 0);
            var o13 = i11 - a10;
            e22.redrawTotalTime += o13, e22.lastRedrawTime = o13, e22.averageRedrawTime = e22.averageRedrawTime / 2 + o13 / 2, e22.requestedFrame = false;
          } else
            xs(e22, false, r10);
          e22.skipFrame = false, se(n13);
        }
      });
    }
  };
  var ws = function(e22) {
    this.init(e22);
  };
  var Es = ws.prototype;
  Es.clientFunctions = ["redrawHint", "render", "renderTo", "matchCanvasSize", "nodeShapeImpl", "arrowShapeImpl"], Es.init = function(e22) {
    var t17 = this;
    t17.options = e22, t17.cy = e22.cy;
    var n13 = t17.container = e22.cy.container(), r10 = t17.cy.window();
    if (r10) {
      var a10 = r10.document, i11 = a10.head, o13 = "__________cytoscape_stylesheet", s11 = "__________cytoscape_container", l11 = null != a10.getElementById(o13);
      if (n13.className.indexOf(s11) < 0 && (n13.className = (n13.className || "") + " " + s11), !l11) {
        var u10 = a10.createElement("style");
        u10.id = o13, u10.textContent = "." + s11 + " { position: relative; }", i11.insertBefore(u10, i11.children[0]);
      }
      "static" === r10.getComputedStyle(n13).getPropertyValue("position") && Me("A Cytoscape container has style position:static and so can not use UI extensions properly");
    }
    t17.selection = [void 0, void 0, void 0, void 0, 0], t17.bezierProjPcts = [0.05, 0.225, 0.4, 0.5, 0.6, 0.775, 0.95], t17.hoverData = { down: null, last: null, downTime: null, triggerMode: null, dragging: false, initialPan: [null, null], capture: false }, t17.dragData = { possibleDragElements: [] }, t17.touchData = { start: null, capture: false, startPosition: [null, null, null, null, null, null], singleTouchStartTime: null, singleTouchMoved: true, now: [null, null, null, null, null, null], earlier: [null, null, null, null, null, null] }, t17.redraws = 0, t17.showFps = e22.showFps, t17.debug = e22.debug, t17.hideEdgesOnViewport = e22.hideEdgesOnViewport, t17.textureOnViewport = e22.textureOnViewport, t17.wheelSensitivity = e22.wheelSensitivity, t17.motionBlurEnabled = e22.motionBlur, t17.forcedPixelRatio = I6(e22.pixelRatio) ? e22.pixelRatio : null, t17.motionBlur = e22.motionBlur, t17.motionBlurOpacity = e22.motionBlurOpacity, t17.motionBlurTransparency = 1 - t17.motionBlurOpacity, t17.motionBlurPxRatio = 1, t17.mbPxRBlurry = 1, t17.minMbLowQualFrames = 4, t17.fullQualityMb = false, t17.clearedForMotionBlur = [], t17.desktopTapThreshold = e22.desktopTapThreshold, t17.desktopTapThreshold2 = e22.desktopTapThreshold * e22.desktopTapThreshold, t17.touchTapThreshold = e22.touchTapThreshold, t17.touchTapThreshold2 = e22.touchTapThreshold * e22.touchTapThreshold, t17.tapholdDuration = 500, t17.bindings = [], t17.beforeRenderCallbacks = [], t17.beforeRenderPriorities = { animations: 400, eleCalcs: 300, eleTxrDeq: 200, lyrTxrDeq: 150, lyrTxrSkip: 100 }, t17.registerNodeShapes(), t17.registerArrowShapes(), t17.registerCalculationListeners();
  }, Es.notify = function(e22, t17) {
    var n13 = this, r10 = n13.cy;
    this.destroyed || ("init" !== e22 ? "destroy" !== e22 ? (("add" === e22 || "remove" === e22 || "move" === e22 && r10.hasCompoundNodes() || "load" === e22 || "zorder" === e22 || "mount" === e22) && n13.invalidateCachedZSortedEles(), "viewport" === e22 && n13.redrawHint("select", true), "load" !== e22 && "resize" !== e22 && "mount" !== e22 || (n13.invalidateContainerClientCoordsCache(), n13.matchCanvasSize(n13.container)), n13.redrawHint("eles", true), n13.redrawHint("drag", true), this.startRenderLoop(), this.redraw()) : n13.destroy() : n13.load());
  }, Es.destroy = function() {
    var e22 = this;
    e22.destroyed = true, e22.cy.stopAnimationLoop();
    for (var t17 = 0; t17 < e22.bindings.length; t17++) {
      var n13 = e22.bindings[t17], r10 = n13.target;
      (r10.off || r10.removeEventListener).apply(r10, n13.args);
    }
    if (e22.bindings = [], e22.beforeRenderCallbacks = [], e22.onUpdateEleCalcsFns = [], e22.removeObserver && e22.removeObserver.disconnect(), e22.styleObserver && e22.styleObserver.disconnect(), e22.resizeObserver && e22.resizeObserver.disconnect(), e22.labelCalcDiv)
      try {
        document.body.removeChild(e22.labelCalcDiv);
      } catch (e23) {
      }
  }, Es.isHeadless = function() {
    return false;
  }, [es, gs, vs, ys, ms, bs].forEach(function(e22) {
    J4(Es, e22);
  });
  var ks = 1e3 / 60;
  var Cs = function(e22) {
    return function() {
      var t17 = this, n13 = this.renderer;
      if (!t17.dequeueingSetup) {
        t17.dequeueingSetup = true;
        var r10 = c6.default(function() {
          n13.redrawHint("eles", true), n13.redrawHint("drag", true), n13.redraw();
        }, e22.deqRedrawThreshold), a10 = e22.priority || De;
        n13.beforeRender(function(a11, i11) {
          var o13 = le(), s11 = n13.averageRedrawTime, l11 = n13.lastRedrawTime, u10 = [], c10 = n13.cy.extent(), d12 = n13.getPixelRatio();
          for (a11 || n13.flushRenderedStyleQueue(); ; ) {
            var h10 = le(), p10 = h10 - o13, f11 = h10 - i11;
            if (l11 < ks) {
              var g9 = ks - (a11 ? s11 : 0);
              if (f11 >= e22.deqFastCost * g9)
                break;
            } else if (a11) {
              if (p10 >= e22.deqCost * l11 || p10 >= e22.deqAvgCost * s11)
                break;
            } else if (f11 >= e22.deqNoDrawCost * ks)
              break;
            var v12 = e22.deq(t17, d12, c10);
            if (!(v12.length > 0))
              break;
            for (var y10 = 0; y10 < v12.length; y10++)
              u10.push(v12[y10]);
          }
          u10.length > 0 && (e22.onDeqd(t17, u10), !a11 && e22.shouldRedraw(t17, u10, d12, c10) && r10());
        }, a10(t17));
      }
    };
  };
  var Ss = function() {
    function e22(t17) {
      var n13 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : Ce;
      v6(this, e22), this.idsByKey = new Ve(), this.keyForId = new Ve(), this.cachesByLvl = new Ve(), this.lvls = [], this.getKey = t17, this.doesEleInvalidateKey = n13;
    }
    return m7(e22, [{ key: "getIdsFor", value: function(e23) {
      null == e23 && Pe("Can not get id list for null key");
      var t17 = this.idsByKey, n13 = this.idsByKey.get(e23);
      return n13 || (n13 = new qe(), t17.set(e23, n13)), n13;
    } }, { key: "addIdForKey", value: function(e23, t17) {
      null != e23 && this.getIdsFor(e23).add(t17);
    } }, { key: "deleteIdForKey", value: function(e23, t17) {
      null != e23 && this.getIdsFor(e23).delete(t17);
    } }, { key: "getNumberOfIdsForKey", value: function(e23) {
      return null == e23 ? 0 : this.getIdsFor(e23).size;
    } }, { key: "updateKeyMappingFor", value: function(e23) {
      var t17 = e23.id(), n13 = this.keyForId.get(t17), r10 = this.getKey(e23);
      this.deleteIdForKey(n13, t17), this.addIdForKey(r10, t17), this.keyForId.set(t17, r10);
    } }, { key: "deleteKeyMappingFor", value: function(e23) {
      var t17 = e23.id(), n13 = this.keyForId.get(t17);
      this.deleteIdForKey(n13, t17), this.keyForId.delete(t17);
    } }, { key: "keyHasChangedFor", value: function(e23) {
      var t17 = e23.id();
      return this.keyForId.get(t17) !== this.getKey(e23);
    } }, { key: "isInvalid", value: function(e23) {
      return this.keyHasChangedFor(e23) || this.doesEleInvalidateKey(e23);
    } }, { key: "getCachesAt", value: function(e23) {
      var t17 = this.cachesByLvl, n13 = this.lvls, r10 = t17.get(e23);
      return r10 || (r10 = new Ve(), t17.set(e23, r10), n13.push(e23)), r10;
    } }, { key: "getCache", value: function(e23, t17) {
      return this.getCachesAt(t17).get(e23);
    } }, { key: "get", value: function(e23, t17) {
      var n13 = this.getKey(e23), r10 = this.getCache(n13, t17);
      return null != r10 && this.updateKeyMappingFor(e23), r10;
    } }, { key: "getForCachedKey", value: function(e23, t17) {
      var n13 = this.keyForId.get(e23.id());
      return this.getCache(n13, t17);
    } }, { key: "hasCache", value: function(e23, t17) {
      return this.getCachesAt(t17).has(e23);
    } }, { key: "has", value: function(e23, t17) {
      var n13 = this.getKey(e23);
      return this.hasCache(n13, t17);
    } }, { key: "setCache", value: function(e23, t17, n13) {
      n13.key = e23, this.getCachesAt(t17).set(e23, n13);
    } }, { key: "set", value: function(e23, t17, n13) {
      var r10 = this.getKey(e23);
      this.setCache(r10, t17, n13), this.updateKeyMappingFor(e23);
    } }, { key: "deleteCache", value: function(e23, t17) {
      this.getCachesAt(t17).delete(e23);
    } }, { key: "delete", value: function(e23, t17) {
      var n13 = this.getKey(e23);
      this.deleteCache(n13, t17);
    } }, { key: "invalidateKey", value: function(e23) {
      var t17 = this;
      this.lvls.forEach(function(n13) {
        return t17.deleteCache(e23, n13);
      });
    } }, { key: "invalidate", value: function(e23) {
      var t17 = e23.id(), n13 = this.keyForId.get(t17);
      this.deleteKeyMappingFor(e23);
      var r10 = this.doesEleInvalidateKey(e23);
      return r10 && this.invalidateKey(n13), r10 || 0 === this.getNumberOfIdsForKey(n13);
    } }]), e22;
  }();
  var Ds = { dequeue: "dequeue", downscale: "downscale", highQuality: "highQuality" };
  var Ps = ze({ getKey: null, doesEleInvalidateKey: Ce, drawElement: null, getBoundingBox: null, getRotationPoint: null, getRotationOffset: null, isVisible: ke, allowEdgeTxrCaching: true, allowParentTxrCaching: true });
  var Ts = function(e22, t17) {
    var n13 = this;
    n13.renderer = e22, n13.onDequeues = [];
    var r10 = Ps(t17);
    J4(n13, r10), n13.lookup = new Ss(r10.getKey, r10.doesEleInvalidateKey), n13.setupDequeueing();
  };
  var Ms = Ts.prototype;
  Ms.reasons = Ds, Ms.getTextureQueue = function(e22) {
    var t17 = this;
    return t17.eleImgCaches = t17.eleImgCaches || {}, t17.eleImgCaches[e22] = t17.eleImgCaches[e22] || [];
  }, Ms.getRetiredTextureQueue = function(e22) {
    var t17 = this.eleImgCaches.retired = this.eleImgCaches.retired || {};
    return t17[e22] = t17[e22] || [];
  }, Ms.getElementQueue = function() {
    return this.eleCacheQueue = this.eleCacheQueue || new d7.default(function(e22, t17) {
      return t17.reqs - e22.reqs;
    });
  }, Ms.getElementKeyToQueue = function() {
    return this.eleKeyToCacheQueue = this.eleKeyToCacheQueue || {};
  }, Ms.getElement = function(e22, t17, n13, r10, a10) {
    var i11 = this, o13 = this.renderer, s11 = o13.cy.zoom(), l11 = this.lookup;
    if (!t17 || 0 === t17.w || 0 === t17.h || isNaN(t17.w) || isNaN(t17.h) || !e22.visible() || e22.removed())
      return null;
    if (!i11.allowEdgeTxrCaching && e22.isEdge() || !i11.allowParentTxrCaching && e22.isParent())
      return null;
    if (null == r10 && (r10 = Math.ceil(lt4(s11 * n13))), r10 < -4)
      r10 = -4;
    else if (s11 >= 7.99 || r10 > 3)
      return null;
    var u10 = Math.pow(2, r10), c10 = t17.h * u10, d12 = t17.w * u10, h10 = o13.eleTextBiggerThanMin(e22, u10);
    if (!this.isVisible(e22, h10))
      return null;
    var p10, f11 = l11.get(e22, r10);
    if (f11 && f11.invalidated && (f11.invalidated = false, f11.texture.invalidatedWidth -= f11.width), f11)
      return f11;
    if (p10 = c10 <= 25 ? 25 : c10 <= 50 ? 50 : 50 * Math.ceil(c10 / 50), c10 > 1024 || d12 > 1024)
      return null;
    var g9 = i11.getTextureQueue(p10), v12 = g9[g9.length - 2], y10 = function() {
      return i11.recycleTexture(p10, d12) || i11.addTexture(p10, d12);
    };
    v12 || (v12 = g9[g9.length - 1]), v12 || (v12 = y10()), v12.width - v12.usedWidth < d12 && (v12 = y10());
    for (var m12, b11 = function(e23) {
      return e23 && e23.scaledLabelShown === h10;
    }, x11 = a10 && a10 === Ds.dequeue, w10 = a10 && a10 === Ds.highQuality, E10 = a10 && a10 === Ds.downscale, k10 = r10 + 1; k10 <= 3; k10++) {
      var C9 = l11.get(e22, k10);
      if (C9) {
        m12 = C9;
        break;
      }
    }
    var S8 = m12 && m12.level === r10 + 1 ? m12 : null, D7 = function() {
      v12.context.drawImage(S8.texture.canvas, S8.x, 0, S8.width, S8.height, v12.usedWidth, 0, d12, c10);
    };
    if (v12.context.setTransform(1, 0, 0, 1, 0, 0), v12.context.clearRect(v12.usedWidth, 0, d12, p10), b11(S8))
      D7();
    else if (b11(m12)) {
      if (!w10)
        return i11.queueElement(e22, m12.level - 1), m12;
      for (var P10 = m12.level; P10 > r10; P10--)
        S8 = i11.getElement(e22, t17, n13, P10, Ds.downscale);
      D7();
    } else {
      var T9;
      if (!x11 && !w10 && !E10)
        for (var M9 = r10 - 1; M9 >= -4; M9--) {
          var B8 = l11.get(e22, M9);
          if (B8) {
            T9 = B8;
            break;
          }
        }
      if (b11(T9))
        return i11.queueElement(e22, r10), T9;
      v12.context.translate(v12.usedWidth, 0), v12.context.scale(u10, u10), this.drawElement(v12.context, e22, t17, h10, false), v12.context.scale(1 / u10, 1 / u10), v12.context.translate(-v12.usedWidth, 0);
    }
    return f11 = { x: v12.usedWidth, texture: v12, level: r10, scale: u10, width: d12, height: c10, scaledLabelShown: h10 }, v12.usedWidth += Math.ceil(d12 + 8), v12.eleCaches.push(f11), l11.set(e22, r10, f11), i11.checkTextureFullness(v12), f11;
  }, Ms.invalidateElements = function(e22) {
    for (var t17 = 0; t17 < e22.length; t17++)
      this.invalidateElement(e22[t17]);
  }, Ms.invalidateElement = function(e22) {
    var t17 = this, n13 = t17.lookup, r10 = [];
    if (n13.isInvalid(e22)) {
      for (var a10 = -4; a10 <= 3; a10++) {
        var i11 = n13.getForCachedKey(e22, a10);
        i11 && r10.push(i11);
      }
      if (n13.invalidate(e22))
        for (var o13 = 0; o13 < r10.length; o13++) {
          var s11 = r10[o13], l11 = s11.texture;
          l11.invalidatedWidth += s11.width, s11.invalidated = true, t17.checkTextureUtility(l11);
        }
      t17.removeFromQueue(e22);
    }
  }, Ms.checkTextureUtility = function(e22) {
    e22.invalidatedWidth >= 0.2 * e22.width && this.retireTexture(e22);
  }, Ms.checkTextureFullness = function(e22) {
    var t17 = this.getTextureQueue(e22.height);
    e22.usedWidth / e22.width > 0.8 && e22.fullnessChecks >= 10 ? Le(t17, e22) : e22.fullnessChecks++;
  }, Ms.retireTexture = function(e22) {
    var t17 = e22.height, n13 = this.getTextureQueue(t17), r10 = this.lookup;
    Le(n13, e22), e22.retired = true;
    for (var a10 = e22.eleCaches, i11 = 0; i11 < a10.length; i11++) {
      var o13 = a10[i11];
      r10.deleteCache(o13.key, o13.level);
    }
    Ae(a10), this.getRetiredTextureQueue(t17).push(e22);
  }, Ms.addTexture = function(e22, t17) {
    var n13 = {};
    return this.getTextureQueue(e22).push(n13), n13.eleCaches = [], n13.height = e22, n13.width = Math.max(1024, t17), n13.usedWidth = 0, n13.invalidatedWidth = 0, n13.fullnessChecks = 0, n13.canvas = this.renderer.makeOffscreenCanvas(n13.width, n13.height), n13.context = n13.canvas.getContext("2d"), n13;
  }, Ms.recycleTexture = function(e22, t17) {
    for (var n13 = this.getTextureQueue(e22), r10 = this.getRetiredTextureQueue(e22), a10 = 0; a10 < r10.length; a10++) {
      var i11 = r10[a10];
      if (i11.width >= t17)
        return i11.retired = false, i11.usedWidth = 0, i11.invalidatedWidth = 0, i11.fullnessChecks = 0, Ae(i11.eleCaches), i11.context.setTransform(1, 0, 0, 1, 0, 0), i11.context.clearRect(0, 0, i11.width, i11.height), Le(r10, i11), n13.push(i11), i11;
    }
  }, Ms.queueElement = function(e22, t17) {
    var n13 = this.getElementQueue(), r10 = this.getElementKeyToQueue(), a10 = this.getKey(e22), i11 = r10[a10];
    if (i11)
      i11.level = Math.max(i11.level, t17), i11.eles.merge(e22), i11.reqs++, n13.updateItem(i11);
    else {
      var o13 = { eles: e22.spawn().merge(e22), level: t17, reqs: 1, key: a10 };
      n13.push(o13), r10[a10] = o13;
    }
  }, Ms.dequeue = function(e22) {
    for (var t17 = this, n13 = t17.getElementQueue(), r10 = t17.getElementKeyToQueue(), a10 = [], i11 = t17.lookup, o13 = 0; o13 < 1 && n13.size() > 0; o13++) {
      var s11 = n13.pop(), l11 = s11.key, u10 = s11.eles[0], c10 = i11.hasCache(u10, s11.level);
      if (r10[l11] = null, !c10) {
        a10.push(s11);
        var d12 = t17.getBoundingBox(u10);
        t17.getElement(u10, d12, e22, s11.level, Ds.dequeue);
      }
    }
    return a10;
  }, Ms.removeFromQueue = function(e22) {
    var t17 = this.getElementQueue(), n13 = this.getElementKeyToQueue(), r10 = this.getKey(e22), a10 = n13[r10];
    null != a10 && (1 === a10.eles.length ? (a10.reqs = Ee, t17.updateItem(a10), t17.pop(), n13[r10] = null) : a10.eles.unmerge(e22));
  }, Ms.onDequeue = function(e22) {
    this.onDequeues.push(e22);
  }, Ms.offDequeue = function(e22) {
    Le(this.onDequeues, e22);
  }, Ms.setupDequeueing = Cs({ deqRedrawThreshold: 100, deqCost: 0.15, deqAvgCost: 0.1, deqNoDrawCost: 0.9, deqFastCost: 0.9, deq: function(e22, t17, n13) {
    return e22.dequeue(t17, n13);
  }, onDeqd: function(e22, t17) {
    for (var n13 = 0; n13 < e22.onDequeues.length; n13++) {
      (0, e22.onDequeues[n13])(t17);
    }
  }, shouldRedraw: function(e22, t17, n13, r10) {
    for (var a10 = 0; a10 < t17.length; a10++)
      for (var i11 = t17[a10].eles, o13 = 0; o13 < i11.length; o13++) {
        var s11 = i11[o13].boundingBox();
        if (wt4(s11, r10))
          return true;
      }
    return false;
  }, priority: function(e22) {
    return e22.renderer.beforeRenderPriorities.eleTxrDeq;
  } });
  var Bs = function(e22) {
    var t17 = this, n13 = t17.renderer = e22, r10 = n13.cy;
    t17.layersByLevel = {}, t17.firstGet = true, t17.lastInvalidationTime = le() - 500, t17.skipping = false, t17.eleTxrDeqs = r10.collection(), t17.scheduleElementRefinement = c6.default(function() {
      t17.refineElementTextures(t17.eleTxrDeqs), t17.eleTxrDeqs.unmerge(t17.eleTxrDeqs);
    }, 50), n13.beforeRender(function(e23, n14) {
      n14 - t17.lastInvalidationTime <= 250 ? t17.skipping = true : t17.skipping = false;
    }, n13.beforeRenderPriorities.lyrTxrSkip);
    t17.layersQueue = new d7.default(function(e23, t18) {
      return t18.reqs - e23.reqs;
    }), t17.setupDequeueing();
  };
  var _s = Bs.prototype;
  var Ns = 0;
  var Is = Math.pow(2, 53) - 1;
  _s.makeLayer = function(e22, t17) {
    var n13 = Math.pow(2, t17), r10 = Math.ceil(e22.w * n13), a10 = Math.ceil(e22.h * n13), i11 = this.renderer.makeOffscreenCanvas(r10, a10), o13 = { id: Ns = ++Ns % Is, bb: e22, level: t17, width: r10, height: a10, canvas: i11, context: i11.getContext("2d"), eles: [], elesQueue: [], reqs: 0 }, s11 = o13.context, l11 = -o13.bb.x1, u10 = -o13.bb.y1;
    return s11.scale(n13, n13), s11.translate(l11, u10), o13;
  }, _s.getLayers = function(e22, t17, n13) {
    var r10 = this, a10 = r10.renderer.cy.zoom(), i11 = r10.firstGet;
    if (r10.firstGet = false, null == n13) {
      if ((n13 = Math.ceil(lt4(a10 * t17))) < -4)
        n13 = -4;
      else if (a10 >= 3.99 || n13 > 2)
        return null;
    }
    r10.validateLayersElesOrdering(n13, e22);
    var o13, s11, l11 = r10.layersByLevel, u10 = Math.pow(2, n13), c10 = l11[n13] = l11[n13] || [];
    if (r10.levelIsComplete(n13, e22))
      return c10;
    !function() {
      var t18 = function(t19) {
        if (r10.validateLayersElesOrdering(t19, e22), r10.levelIsComplete(t19, e22))
          return s11 = l11[t19], true;
      }, a11 = function(e23) {
        if (!s11)
          for (var r11 = n13 + e23; -4 <= r11 && r11 <= 2 && !t18(r11); r11 += e23)
            ;
      };
      a11(1), a11(-1);
      for (var i12 = c10.length - 1; i12 >= 0; i12--) {
        var o14 = c10[i12];
        o14.invalid && Le(c10, o14);
      }
    }();
    var d12 = function(t18) {
      var a11 = (t18 = t18 || {}).after;
      if (function() {
        if (!o13) {
          o13 = vt4();
          for (var t19 = 0; t19 < e22.length; t19++)
            n14 = o13, r11 = e22[t19].boundingBox(), n14.x1 = Math.min(n14.x1, r11.x1), n14.x2 = Math.max(n14.x2, r11.x2), n14.w = n14.x2 - n14.x1, n14.y1 = Math.min(n14.y1, r11.y1), n14.y2 = Math.max(n14.y2, r11.y2), n14.h = n14.y2 - n14.y1;
        }
        var n14, r11;
      }(), o13.w * u10 * (o13.h * u10) > 16e6)
        return null;
      var i12 = r10.makeLayer(o13, n13);
      if (null != a11) {
        var s12 = c10.indexOf(a11) + 1;
        c10.splice(s12, 0, i12);
      } else
        (void 0 === t18.insert || t18.insert) && c10.unshift(i12);
      return i12;
    };
    if (r10.skipping && !i11)
      return null;
    for (var h10 = null, p10 = e22.length / 1, f11 = !i11, g9 = 0; g9 < e22.length; g9++) {
      var v12 = e22[g9], y10 = v12._private.rscratch, m12 = y10.imgLayerCaches = y10.imgLayerCaches || {}, b11 = m12[n13];
      if (b11)
        h10 = b11;
      else {
        if ((!h10 || h10.eles.length >= p10 || !kt4(h10.bb, v12.boundingBox())) && !(h10 = d12({ insert: true, after: h10 })))
          return null;
        s11 || f11 ? r10.queueLayer(h10, v12) : r10.drawEleInLayer(h10, v12, n13, t17), h10.eles.push(v12), m12[n13] = h10;
      }
    }
    return s11 || (f11 ? null : c10);
  }, _s.getEleLevelForLayerLevel = function(e22, t17) {
    return e22;
  }, _s.drawEleInLayer = function(e22, t17, n13, r10) {
    var a10 = this.renderer, i11 = e22.context, o13 = t17.boundingBox();
    0 !== o13.w && 0 !== o13.h && t17.visible() && (n13 = this.getEleLevelForLayerLevel(n13, r10), a10.setImgSmoothing(i11, false), a10.drawCachedElement(i11, t17, null, null, n13, true), a10.setImgSmoothing(i11, true));
  }, _s.levelIsComplete = function(e22, t17) {
    var n13 = this.layersByLevel[e22];
    if (!n13 || 0 === n13.length)
      return false;
    for (var r10 = 0, a10 = 0; a10 < n13.length; a10++) {
      var i11 = n13[a10];
      if (i11.reqs > 0)
        return false;
      if (i11.invalid)
        return false;
      r10 += i11.eles.length;
    }
    return r10 === t17.length;
  }, _s.validateLayersElesOrdering = function(e22, t17) {
    var n13 = this.layersByLevel[e22];
    if (n13)
      for (var r10 = 0; r10 < n13.length; r10++) {
        for (var a10 = n13[r10], i11 = -1, o13 = 0; o13 < t17.length; o13++)
          if (a10.eles[0] === t17[o13]) {
            i11 = o13;
            break;
          }
        if (i11 < 0)
          this.invalidateLayer(a10);
        else {
          var s11 = i11;
          for (o13 = 0; o13 < a10.eles.length; o13++)
            if (a10.eles[o13] !== t17[s11 + o13]) {
              this.invalidateLayer(a10);
              break;
            }
        }
      }
  }, _s.updateElementsInLayers = function(e22, t17) {
    for (var n13 = A6(e22[0]), r10 = 0; r10 < e22.length; r10++)
      for (var a10 = n13 ? null : e22[r10], i11 = n13 ? e22[r10] : e22[r10].ele, o13 = i11._private.rscratch, s11 = o13.imgLayerCaches = o13.imgLayerCaches || {}, l11 = -4; l11 <= 2; l11++) {
        var u10 = s11[l11];
        u10 && (a10 && this.getEleLevelForLayerLevel(u10.level) !== a10.level || t17(u10, i11, a10));
      }
  }, _s.haveLayers = function() {
    for (var e22 = false, t17 = -4; t17 <= 2; t17++) {
      var n13 = this.layersByLevel[t17];
      if (n13 && n13.length > 0) {
        e22 = true;
        break;
      }
    }
    return e22;
  }, _s.invalidateElements = function(e22) {
    var t17 = this;
    0 !== e22.length && (t17.lastInvalidationTime = le(), 0 !== e22.length && t17.haveLayers() && t17.updateElementsInLayers(e22, function(e23, n13, r10) {
      t17.invalidateLayer(e23);
    }));
  }, _s.invalidateLayer = function(e22) {
    if (this.lastInvalidationTime = le(), !e22.invalid) {
      var t17 = e22.level, n13 = e22.eles, r10 = this.layersByLevel[t17];
      Le(r10, e22), e22.elesQueue = [], e22.invalid = true, e22.replacement && (e22.replacement.invalid = true);
      for (var a10 = 0; a10 < n13.length; a10++) {
        var i11 = n13[a10]._private.rscratch.imgLayerCaches;
        i11 && (i11[t17] = null);
      }
    }
  }, _s.refineElementTextures = function(e22) {
    var t17 = this;
    t17.updateElementsInLayers(e22, function(e23, n13, r10) {
      var a10 = e23.replacement;
      if (a10 || ((a10 = e23.replacement = t17.makeLayer(e23.bb, e23.level)).replaces = e23, a10.eles = e23.eles), !a10.reqs)
        for (var i11 = 0; i11 < a10.eles.length; i11++)
          t17.queueLayer(a10, a10.eles[i11]);
    });
  }, _s.enqueueElementRefinement = function(e22) {
    this.eleTxrDeqs.merge(e22), this.scheduleElementRefinement();
  }, _s.queueLayer = function(e22, t17) {
    var n13 = this.layersQueue, r10 = e22.elesQueue, a10 = r10.hasId = r10.hasId || {};
    if (!e22.replacement) {
      if (t17) {
        if (a10[t17.id()])
          return;
        r10.push(t17), a10[t17.id()] = true;
      }
      e22.reqs ? (e22.reqs++, n13.updateItem(e22)) : (e22.reqs = 1, n13.push(e22));
    }
  }, _s.dequeue = function(e22) {
    for (var t17 = this, n13 = t17.layersQueue, r10 = [], a10 = 0; a10 < 1 && 0 !== n13.size(); ) {
      var i11 = n13.peek();
      if (i11.replacement)
        n13.pop();
      else if (i11.replaces && i11 !== i11.replaces.replacement)
        n13.pop();
      else if (i11.invalid)
        n13.pop();
      else {
        var o13 = i11.elesQueue.shift();
        o13 && (t17.drawEleInLayer(i11, o13, i11.level, e22), a10++), 0 === r10.length && r10.push(true), 0 === i11.elesQueue.length && (n13.pop(), i11.reqs = 0, i11.replaces && t17.applyLayerReplacement(i11), t17.requestRedraw());
      }
    }
    return r10;
  }, _s.applyLayerReplacement = function(e22) {
    var t17 = this.layersByLevel[e22.level], n13 = e22.replaces, r10 = t17.indexOf(n13);
    if (!(r10 < 0 || n13.invalid)) {
      t17[r10] = e22;
      for (var a10 = 0; a10 < e22.eles.length; a10++) {
        var i11 = e22.eles[a10]._private, o13 = i11.imgLayerCaches = i11.imgLayerCaches || {};
        o13 && (o13[e22.level] = e22);
      }
      this.requestRedraw();
    }
  }, _s.requestRedraw = c6.default(function() {
    var e22 = this.renderer;
    e22.redrawHint("eles", true), e22.redrawHint("drag", true), e22.redraw();
  }, 100), _s.setupDequeueing = Cs({ deqRedrawThreshold: 50, deqCost: 0.15, deqAvgCost: 0.1, deqNoDrawCost: 0.9, deqFastCost: 0.9, deq: function(e22, t17) {
    return e22.dequeue(t17);
  }, onDeqd: De, shouldRedraw: ke, priority: function(e22) {
    return e22.renderer.beforeRenderPriorities.lyrTxrDeq;
  } });
  var zs;
  var Ls = {};
  function As(e22, t17) {
    for (var n13 = 0; n13 < t17.length; n13++) {
      var r10 = t17[n13];
      e22.lineTo(r10.x, r10.y);
    }
  }
  function Os(e22, t17, n13) {
    for (var r10, a10 = 0; a10 < t17.length; a10++) {
      var i11 = t17[a10];
      0 === a10 && (r10 = i11), e22.lineTo(i11.x, i11.y);
    }
    e22.quadraticCurveTo(n13.x, n13.y, r10.x, r10.y);
  }
  function Rs(e22, t17, n13) {
    e22.beginPath && e22.beginPath();
    for (var r10 = t17, a10 = 0; a10 < r10.length; a10++) {
      var i11 = r10[a10];
      e22.lineTo(i11.x, i11.y);
    }
    var o13 = n13, s11 = n13[0];
    e22.moveTo(s11.x, s11.y);
    for (a10 = 1; a10 < o13.length; a10++) {
      i11 = o13[a10];
      e22.lineTo(i11.x, i11.y);
    }
    e22.closePath && e22.closePath();
  }
  function Vs(e22, t17, n13, r10, a10) {
    e22.beginPath && e22.beginPath(), e22.arc(n13, r10, a10, 0, 2 * Math.PI, false);
    var i11 = t17, o13 = i11[0];
    e22.moveTo(o13.x, o13.y);
    for (var s11 = 0; s11 < i11.length; s11++) {
      var l11 = i11[s11];
      e22.lineTo(l11.x, l11.y);
    }
    e22.closePath && e22.closePath();
  }
  function Fs(e22, t17, n13, r10) {
    e22.arc(t17, n13, r10, 0, 2 * Math.PI, false);
  }
  Ls.arrowShapeImpl = function(e22) {
    return (zs || (zs = { polygon: As, "triangle-backcurve": Os, "triangle-tee": Rs, "circle-triangle": Vs, "triangle-cross": Rs, circle: Fs }))[e22];
  };
  var qs = { drawElement: function(e22, t17, n13, r10, a10, i11) {
    t17.isNode() ? this.drawNode(e22, t17, n13, r10, a10, i11) : this.drawEdge(e22, t17, n13, r10, a10, i11);
  }, drawElementOverlay: function(e22, t17) {
    t17.isNode() ? this.drawNodeOverlay(e22, t17) : this.drawEdgeOverlay(e22, t17);
  }, drawElementUnderlay: function(e22, t17) {
    t17.isNode() ? this.drawNodeUnderlay(e22, t17) : this.drawEdgeUnderlay(e22, t17);
  }, drawCachedElementPortion: function(e22, t17, n13, r10, a10, i11, o13, s11) {
    var l11 = this, u10 = n13.getBoundingBox(t17);
    if (0 !== u10.w && 0 !== u10.h) {
      var c10 = n13.getElement(t17, u10, r10, a10, i11);
      if (null != c10) {
        var d12 = s11(l11, t17);
        if (0 === d12)
          return;
        var h10, p10, f11, g9, v12, y10, m12 = o13(l11, t17), b11 = u10.x1, x11 = u10.y1, w10 = u10.w, E10 = u10.h;
        if (0 !== m12) {
          var k10 = n13.getRotationPoint(t17);
          f11 = k10.x, g9 = k10.y, e22.translate(f11, g9), e22.rotate(m12), (v12 = l11.getImgSmoothing(e22)) || l11.setImgSmoothing(e22, true);
          var C9 = n13.getRotationOffset(t17);
          h10 = C9.x, p10 = C9.y;
        } else
          h10 = b11, p10 = x11;
        1 !== d12 && (y10 = e22.globalAlpha, e22.globalAlpha = y10 * d12), e22.drawImage(c10.texture.canvas, c10.x, 0, c10.width, c10.height, h10, p10, w10, E10), 1 !== d12 && (e22.globalAlpha = y10), 0 !== m12 && (e22.rotate(-m12), e22.translate(-f11, -g9), v12 || l11.setImgSmoothing(e22, false));
      } else
        n13.drawElement(e22, t17);
    }
  } };
  var js = function() {
    return 0;
  };
  var Ys = function(e22, t17) {
    return e22.getTextAngle(t17, null);
  };
  var Xs = function(e22, t17) {
    return e22.getTextAngle(t17, "source");
  };
  var Ws = function(e22, t17) {
    return e22.getTextAngle(t17, "target");
  };
  var Hs = function(e22, t17) {
    return t17.effectiveOpacity();
  };
  var Ks = function(e22, t17) {
    return t17.pstyle("text-opacity").pfValue * t17.effectiveOpacity();
  };
  qs.drawCachedElement = function(e22, t17, n13, r10, a10, i11) {
    var o13 = this, s11 = o13.data, l11 = s11.eleTxrCache, u10 = s11.lblTxrCache, c10 = s11.slbTxrCache, d12 = s11.tlbTxrCache, h10 = t17.boundingBox(), p10 = true === i11 ? l11.reasons.highQuality : null;
    if (0 !== h10.w && 0 !== h10.h && t17.visible() && (!r10 || wt4(h10, r10))) {
      var f11 = t17.isEdge(), g9 = t17.element()._private.rscratch.badLine;
      o13.drawElementUnderlay(e22, t17), o13.drawCachedElementPortion(e22, t17, l11, n13, a10, p10, js, Hs), f11 && g9 || o13.drawCachedElementPortion(e22, t17, u10, n13, a10, p10, Ys, Ks), f11 && !g9 && (o13.drawCachedElementPortion(e22, t17, c10, n13, a10, p10, Xs, Ks), o13.drawCachedElementPortion(e22, t17, d12, n13, a10, p10, Ws, Ks)), o13.drawElementOverlay(e22, t17);
    }
  }, qs.drawElements = function(e22, t17) {
    for (var n13 = 0; n13 < t17.length; n13++) {
      var r10 = t17[n13];
      this.drawElement(e22, r10);
    }
  }, qs.drawCachedElements = function(e22, t17, n13, r10) {
    for (var a10 = 0; a10 < t17.length; a10++) {
      var i11 = t17[a10];
      this.drawCachedElement(e22, i11, n13, r10);
    }
  }, qs.drawCachedNodes = function(e22, t17, n13, r10) {
    for (var a10 = 0; a10 < t17.length; a10++) {
      var i11 = t17[a10];
      i11.isNode() && this.drawCachedElement(e22, i11, n13, r10);
    }
  }, qs.drawLayeredElements = function(e22, t17, n13, r10) {
    var a10 = this.data.lyrTxrCache.getLayers(t17, n13);
    if (a10)
      for (var i11 = 0; i11 < a10.length; i11++) {
        var o13 = a10[i11], s11 = o13.bb;
        0 !== s11.w && 0 !== s11.h && e22.drawImage(o13.canvas, s11.x1, s11.y1, s11.w, s11.h);
      }
    else
      this.drawCachedElements(e22, t17, n13, r10);
  };
  var Gs = { drawEdge: function(e22, t17, n13) {
    var r10 = !(arguments.length > 3 && void 0 !== arguments[3]) || arguments[3], a10 = !(arguments.length > 4 && void 0 !== arguments[4]) || arguments[4], i11 = !(arguments.length > 5 && void 0 !== arguments[5]) || arguments[5], o13 = this, s11 = t17._private.rscratch;
    if ((!i11 || t17.visible()) && !s11.badLine && null != s11.allpts && !isNaN(s11.allpts[0])) {
      var l11;
      n13 && (l11 = n13, e22.translate(-l11.x1, -l11.y1));
      var u10 = i11 ? t17.pstyle("opacity").value : 1, c10 = i11 ? t17.pstyle("line-opacity").value : 1, d12 = t17.pstyle("curve-style").value, h10 = t17.pstyle("line-style").value, p10 = t17.pstyle("width").pfValue, f11 = t17.pstyle("line-cap").value, g9 = u10 * c10, v12 = u10 * c10, y10 = function() {
        var n14 = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : g9;
        "straight-triangle" === d12 ? (o13.eleStrokeStyle(e22, t17, n14), o13.drawEdgeTrianglePath(t17, e22, s11.allpts)) : (e22.lineWidth = p10, e22.lineCap = f11, o13.eleStrokeStyle(e22, t17, n14), o13.drawEdgePath(t17, e22, s11.allpts, h10), e22.lineCap = "butt");
      }, m12 = function() {
        var n14 = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : v12;
        o13.drawArrowheads(e22, t17, n14);
      };
      if (e22.lineJoin = "round", "yes" === t17.pstyle("ghost").value) {
        var b11 = t17.pstyle("ghost-offset-x").pfValue, x11 = t17.pstyle("ghost-offset-y").pfValue, w10 = t17.pstyle("ghost-opacity").value, E10 = g9 * w10;
        e22.translate(b11, x11), y10(E10), m12(E10), e22.translate(-b11, -x11);
      }
      a10 && o13.drawEdgeUnderlay(e22, t17), y10(), m12(), a10 && o13.drawEdgeOverlay(e22, t17), o13.drawElementText(e22, t17, null, r10), n13 && e22.translate(l11.x1, l11.y1);
    }
  } };
  var Us = function(e22) {
    if (!["overlay", "underlay"].includes(e22))
      throw new Error("Invalid state");
    return function(t17, n13) {
      if (n13.visible()) {
        var r10 = n13.pstyle("".concat(e22, "-opacity")).value;
        if (0 !== r10) {
          var a10 = this, i11 = a10.usePaths(), o13 = n13._private.rscratch, s11 = 2 * n13.pstyle("".concat(e22, "-padding")).pfValue, l11 = n13.pstyle("".concat(e22, "-color")).value;
          t17.lineWidth = s11, "self" !== o13.edgeType || i11 ? t17.lineCap = "round" : t17.lineCap = "butt", a10.colorStrokeStyle(t17, l11[0], l11[1], l11[2], r10), a10.drawEdgePath(n13, t17, o13.allpts, "solid");
        }
      }
    };
  };
  Gs.drawEdgeOverlay = Us("overlay"), Gs.drawEdgeUnderlay = Us("underlay"), Gs.drawEdgePath = function(e22, t17, n13, r10) {
    var a10, i11 = e22._private.rscratch, o13 = t17, s11 = false, l11 = this.usePaths(), u10 = e22.pstyle("line-dash-pattern").pfValue, c10 = e22.pstyle("line-dash-offset").pfValue;
    if (l11) {
      var d12 = n13.join("$");
      i11.pathCacheKey && i11.pathCacheKey === d12 ? (a10 = t17 = i11.pathCache, s11 = true) : (a10 = t17 = new Path2D(), i11.pathCacheKey = d12, i11.pathCache = a10);
    }
    if (o13.setLineDash)
      switch (r10) {
        case "dotted":
          o13.setLineDash([1, 1]);
          break;
        case "dashed":
          o13.setLineDash(u10), o13.lineDashOffset = c10;
          break;
        case "solid":
          o13.setLineDash([]);
      }
    if (!s11 && !i11.badLine)
      switch (t17.beginPath && t17.beginPath(), t17.moveTo(n13[0], n13[1]), i11.edgeType) {
        case "bezier":
        case "self":
        case "compound":
        case "multibezier":
          for (var h10 = 2; h10 + 3 < n13.length; h10 += 4)
            t17.quadraticCurveTo(n13[h10], n13[h10 + 1], n13[h10 + 2], n13[h10 + 3]);
          break;
        case "straight":
        case "segments":
        case "haystack":
          for (var p10 = 2; p10 + 1 < n13.length; p10 += 2)
            t17.lineTo(n13[p10], n13[p10 + 1]);
      }
    t17 = o13, l11 ? t17.stroke(a10) : t17.stroke(), t17.setLineDash && t17.setLineDash([]);
  }, Gs.drawEdgeTrianglePath = function(e22, t17, n13) {
    t17.fillStyle = t17.strokeStyle;
    for (var r10 = e22.pstyle("width").pfValue, a10 = 0; a10 + 1 < n13.length; a10 += 2) {
      var i11 = [n13[a10 + 2] - n13[a10], n13[a10 + 3] - n13[a10 + 1]], o13 = Math.sqrt(i11[0] * i11[0] + i11[1] * i11[1]), s11 = [i11[1] / o13, -i11[0] / o13], l11 = [s11[0] * r10 / 2, s11[1] * r10 / 2];
      t17.beginPath(), t17.moveTo(n13[a10] - l11[0], n13[a10 + 1] - l11[1]), t17.lineTo(n13[a10] + l11[0], n13[a10 + 1] + l11[1]), t17.lineTo(n13[a10 + 2], n13[a10 + 3]), t17.closePath(), t17.fill();
    }
  }, Gs.drawArrowheads = function(e22, t17, n13) {
    var r10 = t17._private.rscratch, a10 = "haystack" === r10.edgeType;
    a10 || this.drawArrowhead(e22, t17, "source", r10.arrowStartX, r10.arrowStartY, r10.srcArrowAngle, n13), this.drawArrowhead(e22, t17, "mid-target", r10.midX, r10.midY, r10.midtgtArrowAngle, n13), this.drawArrowhead(e22, t17, "mid-source", r10.midX, r10.midY, r10.midsrcArrowAngle, n13), a10 || this.drawArrowhead(e22, t17, "target", r10.arrowEndX, r10.arrowEndY, r10.tgtArrowAngle, n13);
  }, Gs.drawArrowhead = function(e22, t17, n13, r10, a10, i11, o13) {
    if (!(isNaN(r10) || null == r10 || isNaN(a10) || null == a10 || isNaN(i11) || null == i11)) {
      var s11 = this, l11 = t17.pstyle(n13 + "-arrow-shape").value;
      if ("none" !== l11) {
        var u10 = "hollow" === t17.pstyle(n13 + "-arrow-fill").value ? "both" : "filled", c10 = t17.pstyle(n13 + "-arrow-fill").value, d12 = t17.pstyle("width").pfValue, h10 = t17.pstyle("opacity").value;
        void 0 === o13 && (o13 = h10);
        var p10 = e22.globalCompositeOperation;
        1 === o13 && "hollow" !== c10 || (e22.globalCompositeOperation = "destination-out", s11.colorFillStyle(e22, 255, 255, 255, 1), s11.colorStrokeStyle(e22, 255, 255, 255, 1), s11.drawArrowShape(t17, e22, u10, d12, l11, r10, a10, i11), e22.globalCompositeOperation = p10);
        var f11 = t17.pstyle(n13 + "-arrow-color").value;
        s11.colorFillStyle(e22, f11[0], f11[1], f11[2], o13), s11.colorStrokeStyle(e22, f11[0], f11[1], f11[2], o13), s11.drawArrowShape(t17, e22, c10, d12, l11, r10, a10, i11);
      }
    }
  }, Gs.drawArrowShape = function(e22, t17, n13, r10, a10, i11, o13, s11) {
    var l11, u10 = this, c10 = this.usePaths() && "triangle-cross" !== a10, d12 = false, h10 = t17, p10 = { x: i11, y: o13 }, f11 = e22.pstyle("arrow-scale").value, g9 = this.getArrowWidth(r10, f11), v12 = u10.arrowShapes[a10];
    if (c10) {
      var y10 = u10.arrowPathCache = u10.arrowPathCache || [], m12 = ve(a10), b11 = y10[m12];
      null != b11 ? (l11 = t17 = b11, d12 = true) : (l11 = t17 = new Path2D(), y10[m12] = l11);
    }
    d12 || (t17.beginPath && t17.beginPath(), c10 ? v12.draw(t17, 1, 0, { x: 0, y: 0 }, 1) : v12.draw(t17, g9, s11, p10, r10), t17.closePath && t17.closePath()), t17 = h10, c10 && (t17.translate(i11, o13), t17.rotate(s11), t17.scale(g9, g9)), "filled" !== n13 && "both" !== n13 || (c10 ? t17.fill(l11) : t17.fill()), "hollow" !== n13 && "both" !== n13 || (t17.lineWidth = (v12.matchEdgeWidth ? r10 : 1) / (c10 ? g9 : 1), t17.lineJoin = "miter", c10 ? t17.stroke(l11) : t17.stroke()), c10 && (t17.scale(1 / g9, 1 / g9), t17.rotate(-s11), t17.translate(-i11, -o13));
  };
  var Zs = { safeDrawImage: function(e22, t17, n13, r10, a10, i11, o13, s11, l11, u10) {
    if (!(a10 <= 0 || i11 <= 0 || l11 <= 0 || u10 <= 0))
      try {
        e22.drawImage(t17, n13, r10, a10, i11, o13, s11, l11, u10);
      } catch (e23) {
        Me(e23);
      }
  }, drawInscribedImage: function(e22, t17, n13, r10, a10) {
    var i11 = this, o13 = n13.position(), s11 = o13.x, l11 = o13.y, u10 = n13.cy().style(), c10 = u10.getIndexedStyle.bind(u10), d12 = c10(n13, "background-fit", "value", r10), h10 = c10(n13, "background-repeat", "value", r10), p10 = n13.width(), f11 = n13.height(), g9 = 2 * n13.padding(), v12 = p10 + ("inner" === c10(n13, "background-width-relative-to", "value", r10) ? 0 : g9), y10 = f11 + ("inner" === c10(n13, "background-height-relative-to", "value", r10) ? 0 : g9), m12 = n13._private.rscratch, b11 = "node" === c10(n13, "background-clip", "value", r10), x11 = c10(n13, "background-image-opacity", "value", r10) * a10, w10 = c10(n13, "background-image-smoothing", "value", r10), E10 = t17.width || t17.cachedW, k10 = t17.height || t17.cachedH;
    null != E10 && null != k10 || (document.body.appendChild(t17), E10 = t17.cachedW = t17.width || t17.offsetWidth, k10 = t17.cachedH = t17.height || t17.offsetHeight, document.body.removeChild(t17));
    var C9 = E10, S8 = k10;
    if ("auto" !== c10(n13, "background-width", "value", r10) && (C9 = "%" === c10(n13, "background-width", "units", r10) ? c10(n13, "background-width", "pfValue", r10) * v12 : c10(n13, "background-width", "pfValue", r10)), "auto" !== c10(n13, "background-height", "value", r10) && (S8 = "%" === c10(n13, "background-height", "units", r10) ? c10(n13, "background-height", "pfValue", r10) * y10 : c10(n13, "background-height", "pfValue", r10)), 0 !== C9 && 0 !== S8) {
      if ("contain" === d12)
        C9 *= D7 = Math.min(v12 / C9, y10 / S8), S8 *= D7;
      else if ("cover" === d12) {
        var D7;
        C9 *= D7 = Math.max(v12 / C9, y10 / S8), S8 *= D7;
      }
      var P10 = s11 - v12 / 2, T9 = c10(n13, "background-position-x", "units", r10), M9 = c10(n13, "background-position-x", "pfValue", r10);
      P10 += "%" === T9 ? (v12 - C9) * M9 : M9;
      var B8 = c10(n13, "background-offset-x", "units", r10), _7 = c10(n13, "background-offset-x", "pfValue", r10);
      P10 += "%" === B8 ? (v12 - C9) * _7 : _7;
      var N8 = l11 - y10 / 2, I8 = c10(n13, "background-position-y", "units", r10), z8 = c10(n13, "background-position-y", "pfValue", r10);
      N8 += "%" === I8 ? (y10 - S8) * z8 : z8;
      var L10 = c10(n13, "background-offset-y", "units", r10), A10 = c10(n13, "background-offset-y", "pfValue", r10);
      N8 += "%" === L10 ? (y10 - S8) * A10 : A10, m12.pathCache && (P10 -= s11, N8 -= l11, s11 = 0, l11 = 0);
      var O9 = e22.globalAlpha;
      e22.globalAlpha = x11;
      var R8 = i11.getImgSmoothing(e22), V8 = false;
      if ("no" === w10 && R8 ? (i11.setImgSmoothing(e22, false), V8 = true) : "yes" !== w10 || R8 || (i11.setImgSmoothing(e22, true), V8 = true), "no-repeat" === h10)
        b11 && (e22.save(), m12.pathCache ? e22.clip(m12.pathCache) : (i11.nodeShapes[i11.getNodeShape(n13)].draw(e22, s11, l11, v12, y10), e22.clip())), i11.safeDrawImage(e22, t17, 0, 0, E10, k10, P10, N8, C9, S8), b11 && e22.restore();
      else {
        var F9 = e22.createPattern(t17, h10);
        e22.fillStyle = F9, i11.nodeShapes[i11.getNodeShape(n13)].draw(e22, s11, l11, v12, y10), e22.translate(P10, N8), e22.fill(), e22.translate(-P10, -N8);
      }
      e22.globalAlpha = O9, V8 && i11.setImgSmoothing(e22, R8);
    }
  } };
  var $s = {};
  $s.eleTextBiggerThanMin = function(e22, t17) {
    if (!t17) {
      var n13 = e22.cy().zoom(), r10 = this.getPixelRatio(), a10 = Math.ceil(lt4(n13 * r10));
      t17 = Math.pow(2, a10);
    }
    return !(e22.pstyle("font-size").pfValue * t17 < e22.pstyle("min-zoomed-font-size").pfValue);
  }, $s.drawElementText = function(e22, t17, n13, r10, a10) {
    var i11 = !(arguments.length > 5 && void 0 !== arguments[5]) || arguments[5], o13 = this;
    if (null == r10) {
      if (i11 && !o13.eleTextBiggerThanMin(t17))
        return;
    } else if (false === r10)
      return;
    if (t17.isNode()) {
      var s11 = t17.pstyle("label");
      if (!s11 || !s11.value)
        return;
      var l11 = o13.getLabelJustification(t17);
      e22.textAlign = l11, e22.textBaseline = "bottom";
    } else {
      var u10 = t17.element()._private.rscratch.badLine, c10 = t17.pstyle("label"), d12 = t17.pstyle("source-label"), h10 = t17.pstyle("target-label");
      if (u10 || (!c10 || !c10.value) && (!d12 || !d12.value) && (!h10 || !h10.value))
        return;
      e22.textAlign = "center", e22.textBaseline = "bottom";
    }
    var p10, f11 = !n13;
    n13 && (p10 = n13, e22.translate(-p10.x1, -p10.y1)), null == a10 ? (o13.drawText(e22, t17, null, f11, i11), t17.isEdge() && (o13.drawText(e22, t17, "source", f11, i11), o13.drawText(e22, t17, "target", f11, i11))) : o13.drawText(e22, t17, a10, f11, i11), n13 && e22.translate(p10.x1, p10.y1);
  }, $s.getFontCache = function(e22) {
    var t17;
    this.fontCaches = this.fontCaches || [];
    for (var n13 = 0; n13 < this.fontCaches.length; n13++)
      if ((t17 = this.fontCaches[n13]).context === e22)
        return t17;
    return t17 = { context: e22 }, this.fontCaches.push(t17), t17;
  }, $s.setupTextStyle = function(e22, t17) {
    var n13 = !(arguments.length > 2 && void 0 !== arguments[2]) || arguments[2], r10 = t17.pstyle("font-style").strValue, a10 = t17.pstyle("font-size").pfValue + "px", i11 = t17.pstyle("font-family").strValue, o13 = t17.pstyle("font-weight").strValue, s11 = n13 ? t17.effectiveOpacity() * t17.pstyle("text-opacity").value : 1, l11 = t17.pstyle("text-outline-opacity").value * s11, u10 = t17.pstyle("color").value, c10 = t17.pstyle("text-outline-color").value;
    e22.font = r10 + " " + o13 + " " + a10 + " " + i11, e22.lineJoin = "round", this.colorFillStyle(e22, u10[0], u10[1], u10[2], s11), this.colorStrokeStyle(e22, c10[0], c10[1], c10[2], l11);
  }, $s.getTextAngle = function(e22, t17) {
    var n13 = e22._private.rscratch, r10 = t17 ? t17 + "-" : "", a10 = e22.pstyle(r10 + "text-rotation"), i11 = Oe(n13, "labelAngle", t17);
    return "autorotate" === a10.strValue ? e22.isEdge() ? i11 : 0 : "none" === a10.strValue ? 0 : a10.pfValue;
  }, $s.drawText = function(e22, t17, n13) {
    var r10 = !(arguments.length > 3 && void 0 !== arguments[3]) || arguments[3], a10 = !(arguments.length > 4 && void 0 !== arguments[4]) || arguments[4], i11 = t17._private.rscratch, o13 = a10 ? t17.effectiveOpacity() : 1;
    if (!a10 || 0 !== o13 && 0 !== t17.pstyle("text-opacity").value) {
      "main" === n13 && (n13 = null);
      var s11, l11, u10 = Oe(i11, "labelX", n13), c10 = Oe(i11, "labelY", n13), d12 = this.getLabelText(t17, n13);
      if (null != d12 && "" !== d12 && !isNaN(u10) && !isNaN(c10)) {
        this.setupTextStyle(e22, t17, a10);
        var h10, p10 = n13 ? n13 + "-" : "", f11 = Oe(i11, "labelWidth", n13), g9 = Oe(i11, "labelHeight", n13), v12 = t17.pstyle(p10 + "text-margin-x").pfValue, y10 = t17.pstyle(p10 + "text-margin-y").pfValue, m12 = t17.isEdge(), b11 = t17.pstyle("text-halign").value, x11 = t17.pstyle("text-valign").value;
        switch (m12 && (b11 = "center", x11 = "center"), u10 += v12, c10 += y10, 0 !== (h10 = r10 ? this.getTextAngle(t17, n13) : 0) && (s11 = u10, l11 = c10, e22.translate(s11, l11), e22.rotate(h10), u10 = 0, c10 = 0), x11) {
          case "top":
            break;
          case "center":
            c10 += g9 / 2;
            break;
          case "bottom":
            c10 += g9;
        }
        var w10 = t17.pstyle("text-background-opacity").value, E10 = t17.pstyle("text-border-opacity").value, k10 = t17.pstyle("text-border-width").pfValue, C9 = t17.pstyle("text-background-padding").pfValue;
        if (w10 > 0 || k10 > 0 && E10 > 0) {
          var S8 = u10 - C9;
          switch (b11) {
            case "left":
              S8 -= f11;
              break;
            case "center":
              S8 -= f11 / 2;
          }
          var D7 = c10 - g9 - C9, P10 = f11 + 2 * C9, T9 = g9 + 2 * C9;
          if (w10 > 0) {
            var M9 = e22.fillStyle, B8 = t17.pstyle("text-background-color").value;
            e22.fillStyle = "rgba(" + B8[0] + "," + B8[1] + "," + B8[2] + "," + w10 * o13 + ")", 0 === t17.pstyle("text-background-shape").strValue.indexOf("round") ? function(e23, t18, n14, r11, a11) {
              var i12 = arguments.length > 5 && void 0 !== arguments[5] ? arguments[5] : 5;
              e23.beginPath(), e23.moveTo(t18 + i12, n14), e23.lineTo(t18 + r11 - i12, n14), e23.quadraticCurveTo(t18 + r11, n14, t18 + r11, n14 + i12), e23.lineTo(t18 + r11, n14 + a11 - i12), e23.quadraticCurveTo(t18 + r11, n14 + a11, t18 + r11 - i12, n14 + a11), e23.lineTo(t18 + i12, n14 + a11), e23.quadraticCurveTo(t18, n14 + a11, t18, n14 + a11 - i12), e23.lineTo(t18, n14 + i12), e23.quadraticCurveTo(t18, n14, t18 + i12, n14), e23.closePath(), e23.fill();
            }(e22, S8, D7, P10, T9, 2) : e22.fillRect(S8, D7, P10, T9), e22.fillStyle = M9;
          }
          if (k10 > 0 && E10 > 0) {
            var _7 = e22.strokeStyle, N8 = e22.lineWidth, I8 = t17.pstyle("text-border-color").value, z8 = t17.pstyle("text-border-style").value;
            if (e22.strokeStyle = "rgba(" + I8[0] + "," + I8[1] + "," + I8[2] + "," + E10 * o13 + ")", e22.lineWidth = k10, e22.setLineDash)
              switch (z8) {
                case "dotted":
                  e22.setLineDash([1, 1]);
                  break;
                case "dashed":
                  e22.setLineDash([4, 2]);
                  break;
                case "double":
                  e22.lineWidth = k10 / 4, e22.setLineDash([]);
                  break;
                case "solid":
                  e22.setLineDash([]);
              }
            if (e22.strokeRect(S8, D7, P10, T9), "double" === z8) {
              var L10 = k10 / 2;
              e22.strokeRect(S8 + L10, D7 + L10, P10 - 2 * L10, T9 - 2 * L10);
            }
            e22.setLineDash && e22.setLineDash([]), e22.lineWidth = N8, e22.strokeStyle = _7;
          }
        }
        var A10 = 2 * t17.pstyle("text-outline-width").pfValue;
        if (A10 > 0 && (e22.lineWidth = A10), "wrap" === t17.pstyle("text-wrap").value) {
          var O9 = Oe(i11, "labelWrapCachedLines", n13), R8 = Oe(i11, "labelLineHeight", n13), V8 = f11 / 2, F9 = this.getLabelJustification(t17);
          switch ("auto" === F9 || ("left" === b11 ? "left" === F9 ? u10 += -f11 : "center" === F9 && (u10 += -V8) : "center" === b11 ? "left" === F9 ? u10 += -V8 : "right" === F9 && (u10 += V8) : "right" === b11 && ("center" === F9 ? u10 += V8 : "right" === F9 && (u10 += f11))), x11) {
            case "top":
            case "center":
            case "bottom":
              c10 -= (O9.length - 1) * R8;
          }
          for (var q8 = 0; q8 < O9.length; q8++)
            A10 > 0 && e22.strokeText(O9[q8], u10, c10), e22.fillText(O9[q8], u10, c10), c10 += R8;
        } else
          A10 > 0 && e22.strokeText(d12, u10, c10), e22.fillText(d12, u10, c10);
        0 !== h10 && (e22.rotate(-h10), e22.translate(-s11, -l11));
      }
    }
  };
  var Qs = { drawNode: function(e22, t17, n13) {
    var r10, a10, i11 = !(arguments.length > 3 && void 0 !== arguments[3]) || arguments[3], o13 = !(arguments.length > 4 && void 0 !== arguments[4]) || arguments[4], s11 = !(arguments.length > 5 && void 0 !== arguments[5]) || arguments[5], l11 = this, u10 = t17._private, c10 = u10.rscratch, d12 = t17.position();
    if (I6(d12.x) && I6(d12.y) && (!s11 || t17.visible())) {
      var h10, p10, f11 = s11 ? t17.effectiveOpacity() : 1, g9 = l11.usePaths(), v12 = false, y10 = t17.padding();
      r10 = t17.width() + 2 * y10, a10 = t17.height() + 2 * y10, n13 && (p10 = n13, e22.translate(-p10.x1, -p10.y1));
      for (var m12 = t17.pstyle("background-image").value, b11 = new Array(m12.length), x11 = new Array(m12.length), w10 = 0, E10 = 0; E10 < m12.length; E10++) {
        var k10 = m12[E10];
        if (b11[E10] = null != k10 && "none" !== k10) {
          var C9 = t17.cy().style().getIndexedStyle(t17, "background-image-crossorigin", "value", E10);
          w10++, x11[E10] = l11.getCachedImage(k10, C9, function() {
            u10.backgroundTimestamp = Date.now(), t17.emitAndNotify("background");
          });
        }
      }
      var S8 = t17.pstyle("background-blacken").value, D7 = t17.pstyle("border-width").pfValue, P10 = t17.pstyle("background-opacity").value * f11, T9 = t17.pstyle("border-color").value, M9 = t17.pstyle("border-style").value, B8 = t17.pstyle("border-opacity").value * f11;
      e22.lineJoin = "miter";
      var _7 = function() {
        var n14 = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : P10;
        l11.eleFillStyle(e22, t17, n14);
      }, N8 = function() {
        var t18 = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : B8;
        l11.colorStrokeStyle(e22, T9[0], T9[1], T9[2], t18);
      }, z8 = t17.pstyle("shape").strValue, L10 = t17.pstyle("shape-polygon-points").pfValue;
      if (g9) {
        e22.translate(d12.x, d12.y);
        var A10 = l11.nodePathCache = l11.nodePathCache || [], O9 = ye("polygon" === z8 ? z8 + "," + L10.join(",") : z8, "" + a10, "" + r10), R8 = A10[O9];
        null != R8 ? (h10 = R8, v12 = true, c10.pathCache = h10) : (h10 = new Path2D(), A10[O9] = c10.pathCache = h10);
      }
      var V8 = function() {
        if (!v12) {
          var n14 = d12;
          g9 && (n14 = { x: 0, y: 0 }), l11.nodeShapes[l11.getNodeShape(t17)].draw(h10 || e22, n14.x, n14.y, r10, a10);
        }
        g9 ? e22.fill(h10) : e22.fill();
      }, F9 = function() {
        for (var n14 = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : f11, r11 = !(arguments.length > 1 && void 0 !== arguments[1]) || arguments[1], a11 = u10.backgrounding, i12 = 0, o14 = 0; o14 < x11.length; o14++) {
          var s12 = t17.cy().style().getIndexedStyle(t17, "background-image-containment", "value", o14);
          r11 && "over" === s12 || !r11 && "inside" === s12 ? i12++ : b11[o14] && x11[o14].complete && !x11[o14].error && (i12++, l11.drawInscribedImage(e22, x11[o14], t17, o14, n14));
        }
        u10.backgrounding = !(i12 === w10), a11 !== u10.backgrounding && t17.updateStyle(false);
      }, q8 = function() {
        var n14 = arguments.length > 0 && void 0 !== arguments[0] && arguments[0], i12 = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : f11;
        l11.hasPie(t17) && (l11.drawPie(e22, t17, i12), n14 && (g9 || l11.nodeShapes[l11.getNodeShape(t17)].draw(e22, d12.x, d12.y, r10, a10)));
      }, j9 = function() {
        var t18 = (S8 > 0 ? S8 : -S8) * (arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : f11), n14 = S8 > 0 ? 0 : 255;
        0 !== S8 && (l11.colorFillStyle(e22, n14, n14, n14, t18), g9 ? e22.fill(h10) : e22.fill());
      }, Y6 = function() {
        if (D7 > 0) {
          if (e22.lineWidth = D7, e22.lineCap = "butt", e22.setLineDash)
            switch (M9) {
              case "dotted":
                e22.setLineDash([1, 1]);
                break;
              case "dashed":
                e22.setLineDash([4, 2]);
                break;
              case "solid":
              case "double":
                e22.setLineDash([]);
            }
          if (g9 ? e22.stroke(h10) : e22.stroke(), "double" === M9) {
            e22.lineWidth = D7 / 3;
            var t18 = e22.globalCompositeOperation;
            e22.globalCompositeOperation = "destination-out", g9 ? e22.stroke(h10) : e22.stroke(), e22.globalCompositeOperation = t18;
          }
          e22.setLineDash && e22.setLineDash([]);
        }
      };
      if ("yes" === t17.pstyle("ghost").value) {
        var X6 = t17.pstyle("ghost-offset-x").pfValue, W8 = t17.pstyle("ghost-offset-y").pfValue, H8 = t17.pstyle("ghost-opacity").value, K6 = H8 * f11;
        e22.translate(X6, W8), _7(H8 * P10), V8(), F9(K6, true), N8(H8 * B8), Y6(), q8(0 !== S8 || 0 !== D7), F9(K6, false), j9(K6), e22.translate(-X6, -W8);
      }
      g9 && e22.translate(-d12.x, -d12.y), o13 && l11.drawNodeUnderlay(e22, t17, d12, r10, a10), g9 && e22.translate(d12.x, d12.y), _7(), V8(), F9(f11, true), N8(), Y6(), q8(0 !== S8 || 0 !== D7), F9(f11, false), j9(), g9 && e22.translate(-d12.x, -d12.y), l11.drawElementText(e22, t17, null, i11), o13 && l11.drawNodeOverlay(e22, t17, d12, r10, a10), n13 && e22.translate(p10.x1, p10.y1);
    }
  } };
  var Js = function(e22) {
    if (!["overlay", "underlay"].includes(e22))
      throw new Error("Invalid state");
    return function(t17, n13, r10, a10, i11) {
      if (n13.visible()) {
        var o13 = n13.pstyle("".concat(e22, "-padding")).pfValue, s11 = n13.pstyle("".concat(e22, "-opacity")).value, l11 = n13.pstyle("".concat(e22, "-color")).value, u10 = n13.pstyle("".concat(e22, "-shape")).value;
        if (s11 > 0) {
          if (r10 = r10 || n13.position(), null == a10 || null == i11) {
            var c10 = n13.padding();
            a10 = n13.width() + 2 * c10, i11 = n13.height() + 2 * c10;
          }
          this.colorFillStyle(t17, l11[0], l11[1], l11[2], s11), this.nodeShapes[u10].draw(t17, r10.x, r10.y, a10 + 2 * o13, i11 + 2 * o13), t17.fill();
        }
      }
    };
  };
  Qs.drawNodeOverlay = Js("overlay"), Qs.drawNodeUnderlay = Js("underlay"), Qs.hasPie = function(e22) {
    return (e22 = e22[0])._private.hasPie;
  }, Qs.drawPie = function(e22, t17, n13, r10) {
    t17 = t17[0], r10 = r10 || t17.position();
    var a10 = t17.cy().style(), i11 = t17.pstyle("pie-size"), o13 = r10.x, s11 = r10.y, l11 = t17.width(), u10 = t17.height(), c10 = Math.min(l11, u10) / 2, d12 = 0;
    this.usePaths() && (o13 = 0, s11 = 0), "%" === i11.units ? c10 *= i11.pfValue : void 0 !== i11.pfValue && (c10 = i11.pfValue / 2);
    for (var h10 = 1; h10 <= a10.pieBackgroundN; h10++) {
      var p10 = t17.pstyle("pie-" + h10 + "-background-size").value, f11 = t17.pstyle("pie-" + h10 + "-background-color").value, g9 = t17.pstyle("pie-" + h10 + "-background-opacity").value * n13, v12 = p10 / 100;
      v12 + d12 > 1 && (v12 = 1 - d12);
      var y10 = 1.5 * Math.PI + 2 * Math.PI * d12, m12 = y10 + 2 * Math.PI * v12;
      0 === p10 || d12 >= 1 || d12 + v12 > 1 || (e22.beginPath(), e22.moveTo(o13, s11), e22.arc(o13, s11, c10, y10, m12), e22.closePath(), this.colorFillStyle(e22, f11[0], f11[1], f11[2], g9), e22.fill(), d12 += v12);
    }
  };
  var el = {};
  el.getPixelRatio = function() {
    var e22 = this.data.contexts[0];
    if (null != this.forcedPixelRatio)
      return this.forcedPixelRatio;
    var t17 = e22.backingStorePixelRatio || e22.webkitBackingStorePixelRatio || e22.mozBackingStorePixelRatio || e22.msBackingStorePixelRatio || e22.oBackingStorePixelRatio || e22.backingStorePixelRatio || 1;
    return (window.devicePixelRatio || 1) / t17;
  }, el.paintCache = function(e22) {
    for (var t17, n13 = this.paintCaches = this.paintCaches || [], r10 = true, a10 = 0; a10 < n13.length; a10++)
      if ((t17 = n13[a10]).context === e22) {
        r10 = false;
        break;
      }
    return r10 && (t17 = { context: e22 }, n13.push(t17)), t17;
  }, el.createGradientStyleFor = function(e22, t17, n13, r10, a10) {
    var i11, o13 = this.usePaths(), s11 = n13.pstyle(t17 + "-gradient-stop-colors").value, l11 = n13.pstyle(t17 + "-gradient-stop-positions").pfValue;
    if ("radial-gradient" === r10)
      if (n13.isEdge()) {
        var u10 = n13.sourceEndpoint(), c10 = n13.targetEndpoint(), d12 = n13.midpoint(), h10 = ct4(u10, d12), p10 = ct4(c10, d12);
        i11 = e22.createRadialGradient(d12.x, d12.y, 0, d12.x, d12.y, Math.max(h10, p10));
      } else {
        var f11 = o13 ? { x: 0, y: 0 } : n13.position(), g9 = n13.paddedWidth(), v12 = n13.paddedHeight();
        i11 = e22.createRadialGradient(f11.x, f11.y, 0, f11.x, f11.y, Math.max(g9, v12));
      }
    else if (n13.isEdge()) {
      var y10 = n13.sourceEndpoint(), m12 = n13.targetEndpoint();
      i11 = e22.createLinearGradient(y10.x, y10.y, m12.x, m12.y);
    } else {
      var b11 = o13 ? { x: 0, y: 0 } : n13.position(), x11 = n13.paddedWidth() / 2, w10 = n13.paddedHeight() / 2;
      switch (n13.pstyle("background-gradient-direction").value) {
        case "to-bottom":
          i11 = e22.createLinearGradient(b11.x, b11.y - w10, b11.x, b11.y + w10);
          break;
        case "to-top":
          i11 = e22.createLinearGradient(b11.x, b11.y + w10, b11.x, b11.y - w10);
          break;
        case "to-left":
          i11 = e22.createLinearGradient(b11.x + x11, b11.y, b11.x - x11, b11.y);
          break;
        case "to-right":
          i11 = e22.createLinearGradient(b11.x - x11, b11.y, b11.x + x11, b11.y);
          break;
        case "to-bottom-right":
        case "to-right-bottom":
          i11 = e22.createLinearGradient(b11.x - x11, b11.y - w10, b11.x + x11, b11.y + w10);
          break;
        case "to-top-right":
        case "to-right-top":
          i11 = e22.createLinearGradient(b11.x - x11, b11.y + w10, b11.x + x11, b11.y - w10);
          break;
        case "to-bottom-left":
        case "to-left-bottom":
          i11 = e22.createLinearGradient(b11.x + x11, b11.y - w10, b11.x - x11, b11.y + w10);
          break;
        case "to-top-left":
        case "to-left-top":
          i11 = e22.createLinearGradient(b11.x + x11, b11.y + w10, b11.x - x11, b11.y - w10);
      }
    }
    if (!i11)
      return null;
    for (var E10 = l11.length === s11.length, k10 = s11.length, C9 = 0; C9 < k10; C9++)
      i11.addColorStop(E10 ? l11[C9] : C9 / (k10 - 1), "rgba(" + s11[C9][0] + "," + s11[C9][1] + "," + s11[C9][2] + "," + a10 + ")");
    return i11;
  }, el.gradientFillStyle = function(e22, t17, n13, r10) {
    var a10 = this.createGradientStyleFor(e22, "background", t17, n13, r10);
    if (!a10)
      return null;
    e22.fillStyle = a10;
  }, el.colorFillStyle = function(e22, t17, n13, r10, a10) {
    e22.fillStyle = "rgba(" + t17 + "," + n13 + "," + r10 + "," + a10 + ")";
  }, el.eleFillStyle = function(e22, t17, n13) {
    var r10 = t17.pstyle("background-fill").value;
    if ("linear-gradient" === r10 || "radial-gradient" === r10)
      this.gradientFillStyle(e22, t17, r10, n13);
    else {
      var a10 = t17.pstyle("background-color").value;
      this.colorFillStyle(e22, a10[0], a10[1], a10[2], n13);
    }
  }, el.gradientStrokeStyle = function(e22, t17, n13, r10) {
    var a10 = this.createGradientStyleFor(e22, "line", t17, n13, r10);
    if (!a10)
      return null;
    e22.strokeStyle = a10;
  }, el.colorStrokeStyle = function(e22, t17, n13, r10, a10) {
    e22.strokeStyle = "rgba(" + t17 + "," + n13 + "," + r10 + "," + a10 + ")";
  }, el.eleStrokeStyle = function(e22, t17, n13) {
    var r10 = t17.pstyle("line-fill").value;
    if ("linear-gradient" === r10 || "radial-gradient" === r10)
      this.gradientStrokeStyle(e22, t17, r10, n13);
    else {
      var a10 = t17.pstyle("line-color").value;
      this.colorStrokeStyle(e22, a10[0], a10[1], a10[2], n13);
    }
  }, el.matchCanvasSize = function(e22) {
    var t17 = this, n13 = t17.data, r10 = t17.findContainerClientCoords(), a10 = r10[2], i11 = r10[3], o13 = t17.getPixelRatio(), s11 = t17.motionBlurPxRatio;
    e22 !== t17.data.bufferCanvases[t17.MOTIONBLUR_BUFFER_NODE] && e22 !== t17.data.bufferCanvases[t17.MOTIONBLUR_BUFFER_DRAG] || (o13 = s11);
    var l11, u10 = a10 * o13, c10 = i11 * o13;
    if (u10 !== t17.canvasWidth || c10 !== t17.canvasHeight) {
      t17.fontCaches = null;
      var d12 = n13.canvasContainer;
      d12.style.width = a10 + "px", d12.style.height = i11 + "px";
      for (var h10 = 0; h10 < t17.CANVAS_LAYERS; h10++)
        (l11 = n13.canvases[h10]).width = u10, l11.height = c10, l11.style.width = a10 + "px", l11.style.height = i11 + "px";
      for (h10 = 0; h10 < t17.BUFFER_COUNT; h10++)
        (l11 = n13.bufferCanvases[h10]).width = u10, l11.height = c10, l11.style.width = a10 + "px", l11.style.height = i11 + "px";
      t17.textureMult = 1, o13 <= 1 && (l11 = n13.bufferCanvases[t17.TEXTURE_BUFFER], t17.textureMult = 2, l11.width = u10 * t17.textureMult, l11.height = c10 * t17.textureMult), t17.canvasWidth = u10, t17.canvasHeight = c10;
    }
  }, el.renderTo = function(e22, t17, n13, r10) {
    this.render({ forcedContext: e22, forcedZoom: t17, forcedPan: n13, drawAllLayers: true, forcedPxRatio: r10 });
  }, el.render = function(e22) {
    var t17 = (e22 = e22 || Ie()).forcedContext, n13 = e22.drawAllLayers, r10 = e22.drawOnlyNodeLayer, a10 = e22.forcedZoom, i11 = e22.forcedPan, o13 = this, s11 = void 0 === e22.forcedPxRatio ? this.getPixelRatio() : e22.forcedPxRatio, l11 = o13.cy, u10 = o13.data, c10 = u10.canvasNeedsRedraw, d12 = o13.textureOnViewport && !t17 && (o13.pinching || o13.hoverData.dragging || o13.swipePanning || o13.data.wheelZooming), h10 = void 0 !== e22.motionBlur ? e22.motionBlur : o13.motionBlur, p10 = o13.motionBlurPxRatio, f11 = l11.hasCompoundNodes(), g9 = o13.hoverData.draggingEles, v12 = !(!o13.hoverData.selecting && !o13.touchData.selecting), y10 = h10 = h10 && !t17 && o13.motionBlurEnabled && !v12;
    t17 || (o13.prevPxRatio !== s11 && (o13.invalidateContainerClientCoordsCache(), o13.matchCanvasSize(o13.container), o13.redrawHint("eles", true), o13.redrawHint("drag", true)), o13.prevPxRatio = s11), !t17 && o13.motionBlurTimeout && clearTimeout(o13.motionBlurTimeout), h10 && (null == o13.mbFrames && (o13.mbFrames = 0), o13.mbFrames++, o13.mbFrames < 3 && (y10 = false), o13.mbFrames > o13.minMbLowQualFrames && (o13.motionBlurPxRatio = o13.mbPxRBlurry)), o13.clearingMotionBlur && (o13.motionBlurPxRatio = 1), o13.textureDrawLastFrame && !d12 && (c10[o13.NODE] = true, c10[o13.SELECT_BOX] = true);
    var m12 = l11.style(), b11 = l11.zoom(), x11 = void 0 !== a10 ? a10 : b11, w10 = l11.pan(), E10 = { x: w10.x, y: w10.y }, k10 = { zoom: b11, pan: { x: w10.x, y: w10.y } }, C9 = o13.prevViewport;
    void 0 === C9 || k10.zoom !== C9.zoom || k10.pan.x !== C9.pan.x || k10.pan.y !== C9.pan.y || g9 && !f11 || (o13.motionBlurPxRatio = 1), i11 && (E10 = i11), x11 *= s11, E10.x *= s11, E10.y *= s11;
    var S8 = o13.getCachedZSortedEles();
    function D7(e23, t18, n14, r11, a11) {
      var i12 = e23.globalCompositeOperation;
      e23.globalCompositeOperation = "destination-out", o13.colorFillStyle(e23, 255, 255, 255, o13.motionBlurTransparency), e23.fillRect(t18, n14, r11, a11), e23.globalCompositeOperation = i12;
    }
    function P10(e23, r11) {
      var s12, l12, c11, d13;
      o13.clearingMotionBlur || e23 !== u10.bufferContexts[o13.MOTIONBLUR_BUFFER_NODE] && e23 !== u10.bufferContexts[o13.MOTIONBLUR_BUFFER_DRAG] ? (s12 = E10, l12 = x11, c11 = o13.canvasWidth, d13 = o13.canvasHeight) : (s12 = { x: w10.x * p10, y: w10.y * p10 }, l12 = b11 * p10, c11 = o13.canvasWidth * p10, d13 = o13.canvasHeight * p10), e23.setTransform(1, 0, 0, 1, 0, 0), "motionBlur" === r11 ? D7(e23, 0, 0, c11, d13) : t17 || void 0 !== r11 && !r11 || e23.clearRect(0, 0, c11, d13), n13 || (e23.translate(s12.x, s12.y), e23.scale(l12, l12)), i11 && e23.translate(i11.x, i11.y), a10 && e23.scale(a10, a10);
    }
    if (d12 || (o13.textureDrawLastFrame = false), d12) {
      if (o13.textureDrawLastFrame = true, !o13.textureCache) {
        o13.textureCache = {}, o13.textureCache.bb = l11.mutableElements().boundingBox(), o13.textureCache.texture = o13.data.bufferCanvases[o13.TEXTURE_BUFFER];
        var T9 = o13.data.bufferContexts[o13.TEXTURE_BUFFER];
        T9.setTransform(1, 0, 0, 1, 0, 0), T9.clearRect(0, 0, o13.canvasWidth * o13.textureMult, o13.canvasHeight * o13.textureMult), o13.render({ forcedContext: T9, drawOnlyNodeLayer: true, forcedPxRatio: s11 * o13.textureMult }), (k10 = o13.textureCache.viewport = { zoom: l11.zoom(), pan: l11.pan(), width: o13.canvasWidth, height: o13.canvasHeight }).mpan = { x: (0 - k10.pan.x) / k10.zoom, y: (0 - k10.pan.y) / k10.zoom };
      }
      c10[o13.DRAG] = false, c10[o13.NODE] = false;
      var M9 = u10.contexts[o13.NODE], B8 = o13.textureCache.texture;
      k10 = o13.textureCache.viewport;
      M9.setTransform(1, 0, 0, 1, 0, 0), h10 ? D7(M9, 0, 0, k10.width, k10.height) : M9.clearRect(0, 0, k10.width, k10.height);
      var _7 = m12.core("outside-texture-bg-color").value, N8 = m12.core("outside-texture-bg-opacity").value;
      o13.colorFillStyle(M9, _7[0], _7[1], _7[2], N8), M9.fillRect(0, 0, k10.width, k10.height);
      b11 = l11.zoom();
      P10(M9, false), M9.clearRect(k10.mpan.x, k10.mpan.y, k10.width / k10.zoom / s11, k10.height / k10.zoom / s11), M9.drawImage(B8, k10.mpan.x, k10.mpan.y, k10.width / k10.zoom / s11, k10.height / k10.zoom / s11);
    } else
      o13.textureOnViewport && !t17 && (o13.textureCache = null);
    var I8 = l11.extent(), z8 = o13.pinching || o13.hoverData.dragging || o13.swipePanning || o13.data.wheelZooming || o13.hoverData.draggingEles || o13.cy.animated(), L10 = o13.hideEdgesOnViewport && z8, A10 = [];
    if (A10[o13.NODE] = !c10[o13.NODE] && h10 && !o13.clearedForMotionBlur[o13.NODE] || o13.clearingMotionBlur, A10[o13.NODE] && (o13.clearedForMotionBlur[o13.NODE] = true), A10[o13.DRAG] = !c10[o13.DRAG] && h10 && !o13.clearedForMotionBlur[o13.DRAG] || o13.clearingMotionBlur, A10[o13.DRAG] && (o13.clearedForMotionBlur[o13.DRAG] = true), c10[o13.NODE] || n13 || r10 || A10[o13.NODE]) {
      var O9 = h10 && !A10[o13.NODE] && 1 !== p10;
      P10(M9 = t17 || (O9 ? o13.data.bufferContexts[o13.MOTIONBLUR_BUFFER_NODE] : u10.contexts[o13.NODE]), h10 && !O9 ? "motionBlur" : void 0), L10 ? o13.drawCachedNodes(M9, S8.nondrag, s11, I8) : o13.drawLayeredElements(M9, S8.nondrag, s11, I8), o13.debug && o13.drawDebugPoints(M9, S8.nondrag), n13 || h10 || (c10[o13.NODE] = false);
    }
    if (!r10 && (c10[o13.DRAG] || n13 || A10[o13.DRAG])) {
      O9 = h10 && !A10[o13.DRAG] && 1 !== p10;
      P10(M9 = t17 || (O9 ? o13.data.bufferContexts[o13.MOTIONBLUR_BUFFER_DRAG] : u10.contexts[o13.DRAG]), h10 && !O9 ? "motionBlur" : void 0), L10 ? o13.drawCachedNodes(M9, S8.drag, s11, I8) : o13.drawCachedElements(M9, S8.drag, s11, I8), o13.debug && o13.drawDebugPoints(M9, S8.drag), n13 || h10 || (c10[o13.DRAG] = false);
    }
    if (o13.showFps || !r10 && c10[o13.SELECT_BOX] && !n13) {
      if (P10(M9 = t17 || u10.contexts[o13.SELECT_BOX]), 1 == o13.selection[4] && (o13.hoverData.selecting || o13.touchData.selecting)) {
        b11 = o13.cy.zoom();
        var R8 = m12.core("selection-box-border-width").value / b11;
        M9.lineWidth = R8, M9.fillStyle = "rgba(" + m12.core("selection-box-color").value[0] + "," + m12.core("selection-box-color").value[1] + "," + m12.core("selection-box-color").value[2] + "," + m12.core("selection-box-opacity").value + ")", M9.fillRect(o13.selection[0], o13.selection[1], o13.selection[2] - o13.selection[0], o13.selection[3] - o13.selection[1]), R8 > 0 && (M9.strokeStyle = "rgba(" + m12.core("selection-box-border-color").value[0] + "," + m12.core("selection-box-border-color").value[1] + "," + m12.core("selection-box-border-color").value[2] + "," + m12.core("selection-box-opacity").value + ")", M9.strokeRect(o13.selection[0], o13.selection[1], o13.selection[2] - o13.selection[0], o13.selection[3] - o13.selection[1]));
      }
      if (u10.bgActivePosistion && !o13.hoverData.selecting) {
        b11 = o13.cy.zoom();
        var V8 = u10.bgActivePosistion;
        M9.fillStyle = "rgba(" + m12.core("active-bg-color").value[0] + "," + m12.core("active-bg-color").value[1] + "," + m12.core("active-bg-color").value[2] + "," + m12.core("active-bg-opacity").value + ")", M9.beginPath(), M9.arc(V8.x, V8.y, m12.core("active-bg-size").pfValue / b11, 0, 2 * Math.PI), M9.fill();
      }
      var F9 = o13.lastRedrawTime;
      if (o13.showFps && F9) {
        F9 = Math.round(F9);
        var q8 = Math.round(1e3 / F9);
        M9.setTransform(1, 0, 0, 1, 0, 0), M9.fillStyle = "rgba(255, 0, 0, 0.75)", M9.strokeStyle = "rgba(255, 0, 0, 0.75)", M9.lineWidth = 1, M9.fillText("1 frame = " + F9 + " ms = " + q8 + " fps", 0, 20);
        M9.strokeRect(0, 30, 250, 20), M9.fillRect(0, 30, 250 * Math.min(q8 / 60, 1), 20);
      }
      n13 || (c10[o13.SELECT_BOX] = false);
    }
    if (h10 && 1 !== p10) {
      var j9 = u10.contexts[o13.NODE], Y6 = o13.data.bufferCanvases[o13.MOTIONBLUR_BUFFER_NODE], X6 = u10.contexts[o13.DRAG], W8 = o13.data.bufferCanvases[o13.MOTIONBLUR_BUFFER_DRAG], H8 = function(e23, t18, n14) {
        e23.setTransform(1, 0, 0, 1, 0, 0), n14 || !y10 ? e23.clearRect(0, 0, o13.canvasWidth, o13.canvasHeight) : D7(e23, 0, 0, o13.canvasWidth, o13.canvasHeight);
        var r11 = p10;
        e23.drawImage(t18, 0, 0, o13.canvasWidth * r11, o13.canvasHeight * r11, 0, 0, o13.canvasWidth, o13.canvasHeight);
      };
      (c10[o13.NODE] || A10[o13.NODE]) && (H8(j9, Y6, A10[o13.NODE]), c10[o13.NODE] = false), (c10[o13.DRAG] || A10[o13.DRAG]) && (H8(X6, W8, A10[o13.DRAG]), c10[o13.DRAG] = false);
    }
    o13.prevViewport = k10, o13.clearingMotionBlur && (o13.clearingMotionBlur = false, o13.motionBlurCleared = true, o13.motionBlur = true), h10 && (o13.motionBlurTimeout = setTimeout(function() {
      o13.motionBlurTimeout = null, o13.clearedForMotionBlur[o13.NODE] = false, o13.clearedForMotionBlur[o13.DRAG] = false, o13.motionBlur = false, o13.clearingMotionBlur = !d12, o13.mbFrames = 0, c10[o13.NODE] = true, c10[o13.DRAG] = true, o13.redraw();
    }, 100)), t17 || l11.emit("render");
  };
  for (tl = { drawPolygonPath: function(e22, t17, n13, r10, a10, i11) {
    var o13 = r10 / 2, s11 = a10 / 2;
    e22.beginPath && e22.beginPath(), e22.moveTo(t17 + o13 * i11[0], n13 + s11 * i11[1]);
    for (var l11 = 1; l11 < i11.length / 2; l11++)
      e22.lineTo(t17 + o13 * i11[2 * l11], n13 + s11 * i11[2 * l11 + 1]);
    e22.closePath();
  }, drawRoundPolygonPath: function(e22, t17, n13, r10, a10, i11) {
    var o13 = r10 / 2, s11 = a10 / 2, l11 = Yt4(r10, a10);
    e22.beginPath && e22.beginPath();
    for (var u10 = 0; u10 < i11.length / 4; u10++) {
      var c10, d12 = void 0;
      d12 = 0 === u10 ? i11.length - 2 : 4 * u10 - 2, c10 = 4 * u10 + 2;
      var h10 = t17 + o13 * i11[4 * u10], p10 = n13 + s11 * i11[4 * u10 + 1], f11 = -i11[d12] * i11[c10] - i11[d12 + 1] * i11[c10 + 1], g9 = l11 / Math.tan(Math.acos(f11) / 2), v12 = h10 - g9 * i11[d12], y10 = p10 - g9 * i11[d12 + 1], m12 = h10 + g9 * i11[c10], b11 = p10 + g9 * i11[c10 + 1];
      0 === u10 ? e22.moveTo(v12, y10) : e22.lineTo(v12, y10), e22.arcTo(h10, p10, m12, b11, l11);
    }
    e22.closePath();
  }, drawRoundRectanglePath: function(e22, t17, n13, r10, a10) {
    var i11 = r10 / 2, o13 = a10 / 2, s11 = jt4(r10, a10);
    e22.beginPath && e22.beginPath(), e22.moveTo(t17, n13 - o13), e22.arcTo(t17 + i11, n13 - o13, t17 + i11, n13, s11), e22.arcTo(t17 + i11, n13 + o13, t17, n13 + o13, s11), e22.arcTo(t17 - i11, n13 + o13, t17 - i11, n13, s11), e22.arcTo(t17 - i11, n13 - o13, t17, n13 - o13, s11), e22.lineTo(t17, n13 - o13), e22.closePath();
  }, drawBottomRoundRectanglePath: function(e22, t17, n13, r10, a10) {
    var i11 = r10 / 2, o13 = a10 / 2, s11 = jt4(r10, a10);
    e22.beginPath && e22.beginPath(), e22.moveTo(t17, n13 - o13), e22.lineTo(t17 + i11, n13 - o13), e22.lineTo(t17 + i11, n13), e22.arcTo(t17 + i11, n13 + o13, t17, n13 + o13, s11), e22.arcTo(t17 - i11, n13 + o13, t17 - i11, n13, s11), e22.lineTo(t17 - i11, n13 - o13), e22.lineTo(t17, n13 - o13), e22.closePath();
  }, drawCutRectanglePath: function(e22, t17, n13, r10, a10) {
    var i11 = r10 / 2, o13 = a10 / 2;
    e22.beginPath && e22.beginPath(), e22.moveTo(t17 - i11 + 8, n13 - o13), e22.lineTo(t17 + i11 - 8, n13 - o13), e22.lineTo(t17 + i11, n13 - o13 + 8), e22.lineTo(t17 + i11, n13 + o13 - 8), e22.lineTo(t17 + i11 - 8, n13 + o13), e22.lineTo(t17 - i11 + 8, n13 + o13), e22.lineTo(t17 - i11, n13 + o13 - 8), e22.lineTo(t17 - i11, n13 - o13 + 8), e22.closePath();
  }, drawBarrelPath: function(e22, t17, n13, r10, a10) {
    var i11 = r10 / 2, o13 = a10 / 2, s11 = t17 - i11, l11 = t17 + i11, u10 = n13 - o13, c10 = n13 + o13, d12 = Xt4(r10, a10), h10 = d12.widthOffset, p10 = d12.heightOffset, f11 = d12.ctrlPtOffsetPct * h10;
    e22.beginPath && e22.beginPath(), e22.moveTo(s11, u10 + p10), e22.lineTo(s11, c10 - p10), e22.quadraticCurveTo(s11 + f11, c10, s11 + h10, c10), e22.lineTo(l11 - h10, c10), e22.quadraticCurveTo(l11 - f11, c10, l11, c10 - p10), e22.lineTo(l11, u10 + p10), e22.quadraticCurveTo(l11 - f11, u10, l11 - h10, u10), e22.lineTo(s11 + h10, u10), e22.quadraticCurveTo(s11 + f11, u10, s11, u10 + p10), e22.closePath();
  } }, nl = Math.sin(0), rl = Math.cos(0), al = {}, il = {}, ol = Math.PI / 40, sl = 0 * Math.PI; sl < 2 * Math.PI; sl += ol)
    al[sl] = Math.sin(sl), il[sl] = Math.cos(sl);
  var tl;
  var nl;
  var rl;
  var al;
  var il;
  var ol;
  var sl;
  tl.drawEllipsePath = function(e22, t17, n13, r10, a10) {
    if (e22.beginPath && e22.beginPath(), e22.ellipse)
      e22.ellipse(t17, n13, r10 / 2, a10 / 2, 0, 0, 2 * Math.PI);
    else
      for (var i11, o13, s11 = r10 / 2, l11 = a10 / 2, u10 = 0 * Math.PI; u10 < 2 * Math.PI; u10 += ol)
        i11 = t17 - s11 * al[u10] * nl + s11 * il[u10] * rl, o13 = n13 + l11 * il[u10] * nl + l11 * al[u10] * rl, 0 === u10 ? e22.moveTo(i11, o13) : e22.lineTo(i11, o13);
    e22.closePath();
  };
  var ll = {};
  function ul(e22) {
    var t17 = e22.indexOf(",");
    return e22.substr(t17 + 1);
  }
  function cl(e22, t17, n13) {
    var r10 = function() {
      return t17.toDataURL(n13, e22.quality);
    };
    switch (e22.output) {
      case "blob-promise":
        return new rr4(function(r11, a10) {
          try {
            t17.toBlob(function(e23) {
              null != e23 ? r11(e23) : a10(new Error("`canvas.toBlob()` sent a null value in its callback"));
            }, n13, e22.quality);
          } catch (e23) {
            a10(e23);
          }
        });
      case "blob":
        return function(e23, t18) {
          for (var n14 = atob(e23), r11 = new ArrayBuffer(n14.length), a10 = new Uint8Array(r11), i11 = 0; i11 < n14.length; i11++)
            a10[i11] = n14.charCodeAt(i11);
          return new Blob([r11], { type: t18 });
        }(ul(r10()), n13);
      case "base64":
        return ul(r10());
      default:
        return r10();
    }
  }
  ll.createBuffer = function(e22, t17) {
    var n13 = document.createElement("canvas");
    return n13.width = e22, n13.height = t17, [n13, n13.getContext("2d")];
  }, ll.bufferCanvasImage = function(e22) {
    var t17 = this.cy, n13 = t17.mutableElements().boundingBox(), r10 = this.findContainerClientCoords(), a10 = e22.full ? Math.ceil(n13.w) : r10[2], i11 = e22.full ? Math.ceil(n13.h) : r10[3], o13 = I6(e22.maxWidth) || I6(e22.maxHeight), s11 = this.getPixelRatio(), l11 = 1;
    if (void 0 !== e22.scale)
      a10 *= e22.scale, i11 *= e22.scale, l11 = e22.scale;
    else if (o13) {
      var u10 = 1 / 0, c10 = 1 / 0;
      I6(e22.maxWidth) && (u10 = l11 * e22.maxWidth / a10), I6(e22.maxHeight) && (c10 = l11 * e22.maxHeight / i11), a10 *= l11 = Math.min(u10, c10), i11 *= l11;
    }
    o13 || (a10 *= s11, i11 *= s11, l11 *= s11);
    var d12 = document.createElement("canvas");
    d12.width = a10, d12.height = i11, d12.style.width = a10 + "px", d12.style.height = i11 + "px";
    var h10 = d12.getContext("2d");
    if (a10 > 0 && i11 > 0) {
      h10.clearRect(0, 0, a10, i11), h10.globalCompositeOperation = "source-over";
      var p10 = this.getCachedZSortedEles();
      if (e22.full)
        h10.translate(-n13.x1 * l11, -n13.y1 * l11), h10.scale(l11, l11), this.drawElements(h10, p10), h10.scale(1 / l11, 1 / l11), h10.translate(n13.x1 * l11, n13.y1 * l11);
      else {
        var f11 = t17.pan(), g9 = { x: f11.x * l11, y: f11.y * l11 };
        l11 *= t17.zoom(), h10.translate(g9.x, g9.y), h10.scale(l11, l11), this.drawElements(h10, p10), h10.scale(1 / l11, 1 / l11), h10.translate(-g9.x, -g9.y);
      }
      e22.bg && (h10.globalCompositeOperation = "destination-over", h10.fillStyle = e22.bg, h10.rect(0, 0, a10, i11), h10.fill());
    }
    return d12;
  }, ll.png = function(e22) {
    return cl(e22, this.bufferCanvasImage(e22), "image/png");
  }, ll.jpg = function(e22) {
    return cl(e22, this.bufferCanvasImage(e22), "image/jpeg");
  };
  var dl = { nodeShapeImpl: function(e22, t17, n13, r10, a10, i11, o13) {
    switch (e22) {
      case "ellipse":
        return this.drawEllipsePath(t17, n13, r10, a10, i11);
      case "polygon":
        return this.drawPolygonPath(t17, n13, r10, a10, i11, o13);
      case "round-polygon":
        return this.drawRoundPolygonPath(t17, n13, r10, a10, i11, o13);
      case "roundrectangle":
      case "round-rectangle":
        return this.drawRoundRectanglePath(t17, n13, r10, a10, i11);
      case "cutrectangle":
      case "cut-rectangle":
        return this.drawCutRectanglePath(t17, n13, r10, a10, i11);
      case "bottomroundrectangle":
      case "bottom-round-rectangle":
        return this.drawBottomRoundRectanglePath(t17, n13, r10, a10, i11);
      case "barrel":
        return this.drawBarrelPath(t17, n13, r10, a10, i11);
    }
  } };
  var hl = fl;
  var pl = fl.prototype;
  function fl(e22) {
    var t17 = this;
    t17.data = { canvases: new Array(pl.CANVAS_LAYERS), contexts: new Array(pl.CANVAS_LAYERS), canvasNeedsRedraw: new Array(pl.CANVAS_LAYERS), bufferCanvases: new Array(pl.BUFFER_COUNT), bufferContexts: new Array(pl.CANVAS_LAYERS) };
    var n13 = "-webkit-tap-highlight-color", r10 = "rgba(0,0,0,0)";
    t17.data.canvasContainer = document.createElement("div");
    var a10 = t17.data.canvasContainer.style;
    t17.data.canvasContainer.style[n13] = r10, a10.position = "relative", a10.zIndex = "0", a10.overflow = "hidden";
    var i11 = e22.cy.container();
    i11.appendChild(t17.data.canvasContainer), i11.style[n13] = r10;
    var o13 = { "-webkit-user-select": "none", "-moz-user-select": "-moz-none", "user-select": "none", "-webkit-tap-highlight-color": "rgba(0,0,0,0)", "outline-style": "none" };
    k5 && k5.userAgent.match(/msie|trident|edge/i) && (o13["-ms-touch-action"] = "none", o13["touch-action"] = "none");
    for (var s11 = 0; s11 < pl.CANVAS_LAYERS; s11++) {
      var l11 = t17.data.canvases[s11] = document.createElement("canvas");
      t17.data.contexts[s11] = l11.getContext("2d"), Object.keys(o13).forEach(function(e23) {
        l11.style[e23] = o13[e23];
      }), l11.style.position = "absolute", l11.setAttribute("data-id", "layer" + s11), l11.style.zIndex = String(pl.CANVAS_LAYERS - s11), t17.data.canvasContainer.appendChild(l11), t17.data.canvasNeedsRedraw[s11] = false;
    }
    t17.data.topCanvas = t17.data.canvases[0], t17.data.canvases[pl.NODE].setAttribute("data-id", "layer" + pl.NODE + "-node"), t17.data.canvases[pl.SELECT_BOX].setAttribute("data-id", "layer" + pl.SELECT_BOX + "-selectbox"), t17.data.canvases[pl.DRAG].setAttribute("data-id", "layer" + pl.DRAG + "-drag");
    for (s11 = 0; s11 < pl.BUFFER_COUNT; s11++)
      t17.data.bufferCanvases[s11] = document.createElement("canvas"), t17.data.bufferContexts[s11] = t17.data.bufferCanvases[s11].getContext("2d"), t17.data.bufferCanvases[s11].style.position = "absolute", t17.data.bufferCanvases[s11].setAttribute("data-id", "buffer" + s11), t17.data.bufferCanvases[s11].style.zIndex = String(-s11 - 1), t17.data.bufferCanvases[s11].style.visibility = "hidden";
    t17.pathsEnabled = true;
    var u10 = vt4(), c10 = function(e23) {
      return { x: -e23.w / 2, y: -e23.h / 2 };
    }, d12 = function(e23) {
      return e23.boundingBox(), e23[0]._private.bodyBounds;
    }, h10 = function(e23) {
      return e23.boundingBox(), e23[0]._private.labelBounds.main || u10;
    }, p10 = function(e23) {
      return e23.boundingBox(), e23[0]._private.labelBounds.source || u10;
    }, f11 = function(e23) {
      return e23.boundingBox(), e23[0]._private.labelBounds.target || u10;
    }, g9 = function(e23, t18) {
      return t18;
    }, v12 = function(e23, t18, n14) {
      var r11 = e23 ? e23 + "-" : "";
      return { x: t18.x + n14.pstyle(r11 + "text-margin-x").pfValue, y: t18.y + n14.pstyle(r11 + "text-margin-y").pfValue };
    }, y10 = function(e23, t18, n14) {
      var r11 = e23[0]._private.rscratch;
      return { x: r11[t18], y: r11[n14] };
    }, m12 = t17.data.eleTxrCache = new Ts(t17, { getKey: function(e23) {
      return e23[0]._private.nodeKey;
    }, doesEleInvalidateKey: function(e23) {
      var t18 = e23[0]._private;
      return !(t18.oldBackgroundTimestamp === t18.backgroundTimestamp);
    }, drawElement: function(e23, n14, r11, a11, i12) {
      return t17.drawElement(e23, n14, r11, false, false, i12);
    }, getBoundingBox: d12, getRotationPoint: function(e23) {
      return { x: ((t18 = d12(e23)).x1 + t18.x2) / 2, y: (t18.y1 + t18.y2) / 2 };
      var t18;
    }, getRotationOffset: function(e23) {
      return c10(d12(e23));
    }, allowEdgeTxrCaching: false, allowParentTxrCaching: false }), b11 = t17.data.lblTxrCache = new Ts(t17, { getKey: function(e23) {
      return e23[0]._private.labelStyleKey;
    }, drawElement: function(e23, n14, r11, a11, i12) {
      return t17.drawElementText(e23, n14, r11, a11, "main", i12);
    }, getBoundingBox: h10, getRotationPoint: function(e23) {
      return v12("", y10(e23, "labelX", "labelY"), e23);
    }, getRotationOffset: function(e23) {
      var t18 = h10(e23), n14 = c10(h10(e23));
      if (e23.isNode()) {
        switch (e23.pstyle("text-halign").value) {
          case "left":
            n14.x = -t18.w;
            break;
          case "right":
            n14.x = 0;
        }
        switch (e23.pstyle("text-valign").value) {
          case "top":
            n14.y = -t18.h;
            break;
          case "bottom":
            n14.y = 0;
        }
      }
      return n14;
    }, isVisible: g9 }), x11 = t17.data.slbTxrCache = new Ts(t17, { getKey: function(e23) {
      return e23[0]._private.sourceLabelStyleKey;
    }, drawElement: function(e23, n14, r11, a11, i12) {
      return t17.drawElementText(e23, n14, r11, a11, "source", i12);
    }, getBoundingBox: p10, getRotationPoint: function(e23) {
      return v12("source", y10(e23, "sourceLabelX", "sourceLabelY"), e23);
    }, getRotationOffset: function(e23) {
      return c10(p10(e23));
    }, isVisible: g9 }), w10 = t17.data.tlbTxrCache = new Ts(t17, { getKey: function(e23) {
      return e23[0]._private.targetLabelStyleKey;
    }, drawElement: function(e23, n14, r11, a11, i12) {
      return t17.drawElementText(e23, n14, r11, a11, "target", i12);
    }, getBoundingBox: f11, getRotationPoint: function(e23) {
      return v12("target", y10(e23, "targetLabelX", "targetLabelY"), e23);
    }, getRotationOffset: function(e23) {
      return c10(f11(e23));
    }, isVisible: g9 }), E10 = t17.data.lyrTxrCache = new Bs(t17);
    t17.onUpdateEleCalcs(function(e23, t18) {
      m12.invalidateElements(t18), b11.invalidateElements(t18), x11.invalidateElements(t18), w10.invalidateElements(t18), E10.invalidateElements(t18);
      for (var n14 = 0; n14 < t18.length; n14++) {
        var r11 = t18[n14]._private;
        r11.oldBackgroundTimestamp = r11.backgroundTimestamp;
      }
    });
    var C9 = function(e23) {
      for (var t18 = 0; t18 < e23.length; t18++)
        E10.enqueueElementRefinement(e23[t18].ele);
    };
    m12.onDequeue(C9), b11.onDequeue(C9), x11.onDequeue(C9), w10.onDequeue(C9);
  }
  pl.CANVAS_LAYERS = 3, pl.SELECT_BOX = 0, pl.DRAG = 1, pl.NODE = 2, pl.BUFFER_COUNT = 3, pl.TEXTURE_BUFFER = 0, pl.MOTIONBLUR_BUFFER_NODE = 1, pl.MOTIONBLUR_BUFFER_DRAG = 2, pl.redrawHint = function(e22, t17) {
    var n13 = this;
    switch (e22) {
      case "eles":
        n13.data.canvasNeedsRedraw[pl.NODE] = t17;
        break;
      case "drag":
        n13.data.canvasNeedsRedraw[pl.DRAG] = t17;
        break;
      case "select":
        n13.data.canvasNeedsRedraw[pl.SELECT_BOX] = t17;
    }
  };
  var gl = "undefined" != typeof Path2D;
  pl.path2dEnabled = function(e22) {
    if (void 0 === e22)
      return this.pathsEnabled;
    this.pathsEnabled = !!e22;
  }, pl.usePaths = function() {
    return gl && this.pathsEnabled;
  }, pl.setImgSmoothing = function(e22, t17) {
    null != e22.imageSmoothingEnabled ? e22.imageSmoothingEnabled = t17 : (e22.webkitImageSmoothingEnabled = t17, e22.mozImageSmoothingEnabled = t17, e22.msImageSmoothingEnabled = t17);
  }, pl.getImgSmoothing = function(e22) {
    return null != e22.imageSmoothingEnabled ? e22.imageSmoothingEnabled : e22.webkitImageSmoothingEnabled || e22.mozImageSmoothingEnabled || e22.msImageSmoothingEnabled;
  }, pl.makeOffscreenCanvas = function(e22, t17) {
    var n13;
    return "undefined" !== ("undefined" == typeof OffscreenCanvas ? "undefined" : g6(OffscreenCanvas)) ? n13 = new OffscreenCanvas(e22, t17) : ((n13 = document.createElement("canvas")).width = e22, n13.height = t17), n13;
  }, [Ls, qs, Gs, Zs, $s, Qs, el, tl, ll, dl].forEach(function(e22) {
    J4(pl, e22);
  });
  var vl = [{ type: "layout", extensions: Zo }, { type: "renderer", extensions: [{ name: "null", impl: $o }, { name: "base", impl: ws }, { name: "canvas", impl: hl }] }];
  var yl = {};
  var ml = {};
  function bl(e22, t17, n13) {
    var r10 = n13, a10 = function(n14) {
      Me("Can not register `" + t17 + "` for `" + e22 + "` since `" + n14 + "` already exists in the prototype and can not be overridden");
    };
    if ("core" === e22) {
      if (lo.prototype[t17])
        return a10(t17);
      lo.prototype[t17] = n13;
    } else if ("collection" === e22) {
      if (Ci.prototype[t17])
        return a10(t17);
      Ci.prototype[t17] = n13;
    } else if ("layout" === e22) {
      for (var i11 = function(e23) {
        this.options = e23, n13.call(this, e23), N6(this._private) || (this._private = {}), this._private.cy = e23.cy, this._private.listeners = [], this.createEmitter();
      }, o13 = i11.prototype = Object.create(n13.prototype), s11 = [], l11 = 0; l11 < s11.length; l11++) {
        var u10 = s11[l11];
        o13[u10] = o13[u10] || function() {
          return this;
        };
      }
      o13.start && !o13.run ? o13.run = function() {
        return this.start(), this;
      } : !o13.start && o13.run && (o13.start = function() {
        return this.run(), this;
      });
      var c10 = n13.prototype.stop;
      o13.stop = function() {
        var e23 = this.options;
        if (e23 && e23.animate) {
          var t18 = this.animations;
          if (t18)
            for (var n14 = 0; n14 < t18.length; n14++)
              t18[n14].stop();
        }
        return c10 ? c10.call(this) : this.emit("layoutstop"), this;
      }, o13.destroy || (o13.destroy = function() {
        return this;
      }), o13.cy = function() {
        return this._private.cy;
      };
      var d12 = function(e23) {
        return e23._private.cy;
      }, h10 = { addEventFields: function(e23, t18) {
        t18.layout = e23, t18.cy = d12(e23), t18.target = e23;
      }, bubble: function() {
        return true;
      }, parent: function(e23) {
        return d12(e23);
      } };
      J4(o13, { createEmitter: function() {
        return this._private.emitter = new ja(h10, this), this;
      }, emitter: function() {
        return this._private.emitter;
      }, on: function(e23, t18) {
        return this.emitter().on(e23, t18), this;
      }, one: function(e23, t18) {
        return this.emitter().one(e23, t18), this;
      }, once: function(e23, t18) {
        return this.emitter().one(e23, t18), this;
      }, removeListener: function(e23, t18) {
        return this.emitter().removeListener(e23, t18), this;
      }, removeAllListeners: function() {
        return this.emitter().removeAllListeners(), this;
      }, emit: function(e23, t18) {
        return this.emitter().emit(e23, t18), this;
      } }), ur3.eventAliasesOn(o13), r10 = i11;
    } else if ("renderer" === e22 && "null" !== t17 && "base" !== t17) {
      var p10 = xl("renderer", "base"), f11 = p10.prototype, g9 = n13, v12 = n13.prototype, y10 = function() {
        p10.apply(this, arguments), g9.apply(this, arguments);
      }, m12 = y10.prototype;
      for (var b11 in f11) {
        var x11 = f11[b11];
        if (null != v12[b11])
          return a10(b11);
        m12[b11] = x11;
      }
      for (var w10 in v12)
        m12[w10] = v12[w10];
      f11.clientFunctions.forEach(function(e23) {
        m12[e23] = m12[e23] || function() {
          Pe("Renderer does not implement `renderer." + e23 + "()` on its prototype");
        };
      }), r10 = y10;
    } else if ("__proto__" === e22 || "constructor" === e22 || "prototype" === e22)
      return Pe(e22 + " is an illegal type to be registered, possibly lead to prototype pollutions");
    return ne({ map: yl, keys: [e22, t17], value: r10 });
  }
  function xl(e22, t17) {
    return re({ map: yl, keys: [e22, t17] });
  }
  function wl(e22, t17, n13, r10, a10) {
    return ne({ map: ml, keys: [e22, t17, n13, r10], value: a10 });
  }
  function El(e22, t17, n13, r10) {
    return re({ map: ml, keys: [e22, t17, n13, r10] });
  }
  var kl = function() {
    return 2 === arguments.length ? xl.apply(null, arguments) : 3 === arguments.length ? bl.apply(null, arguments) : 4 === arguments.length ? El.apply(null, arguments) : 5 === arguments.length ? wl.apply(null, arguments) : void Pe("Invalid extension access syntax");
  };
  lo.prototype.extension = kl, vl.forEach(function(e22) {
    e22.extensions.forEach(function(t17) {
      bl(e22.type, t17.name, t17.impl);
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
  }, Sl.selector = function(e22) {
    return this[this.length++] = { selector: e22, properties: [] }, this;
  }, Sl.css = function(e22, t17) {
    var n13 = this.length - 1;
    if (M6(e22))
      this[n13].properties.push({ name: e22, value: t17 });
    else if (N6(e22))
      for (var r10 = e22, a10 = Object.keys(r10), i11 = 0; i11 < a10.length; i11++) {
        var o13 = a10[i11], s11 = r10[o13];
        if (null != s11) {
          var l11 = ro.properties[o13] || ro.properties[X4(o13)];
          if (null != l11) {
            var u10 = l11.name, c10 = s11;
            this[n13].properties.push({ name: u10, value: c10 });
          }
        }
      }
    return this;
  }, Sl.style = Sl.css, Sl.generateStyle = function(e22) {
    var t17 = new ro(e22);
    return this.appendToStyle(t17);
  }, Sl.appendToStyle = function(e22) {
    for (var t17 = 0; t17 < this.length; t17++) {
      var n13 = this[t17], r10 = n13.selector, a10 = n13.properties;
      e22.selector(r10);
      for (var i11 = 0; i11 < a10.length; i11++) {
        var o13 = a10[i11];
        e22.css(o13.name, o13.value);
      }
    }
    return e22;
  };
  var Dl = function(e22) {
    return void 0 === e22 && (e22 = {}), N6(e22) ? new lo(e22) : M6(e22) ? kl.apply(kl, arguments) : void 0;
  };
  Dl.use = function(e22) {
    var t17 = Array.prototype.slice.call(arguments, 1);
    return t17.unshift(Dl), e22.apply(null, t17), this;
  }, Dl.warnings = function(e22) {
    return Te(e22);
  }, Dl.version = "3.26.0", Dl.stylesheet = Dl.Stylesheet = Cl;
  var Pl = Dl;
  var Tl = Pl.stylesheet;
  var Ml = Pl.use;
  var Bl = Pl.version;
  var _l = Pl.warnings;

  // http-url:https://cdn.jsdelivr.net/npm/webcola@3.4.0/+esm
  var t11 = "undefined" != typeof globalThis ? globalThis : "undefined" != typeof window ? window : "undefined" != typeof global ? global : "undefined" != typeof self ? self : {};
  var e16 = {};
  var n8 = {};
  var r6 = {};
  var i7 = {};
  Object.defineProperty(i7, "__esModule", { value: true });
  var o8 = function(t17, e22, n13) {
    this.source = t17, this.target = e22, this.type = n13;
  };
  i7.PowerEdge = o8;
  var s7 = function() {
    function t17(t18, e22, n13, r10) {
      var i11 = this;
      if (this.linkAccessor = n13, this.modules = new Array(t18), this.roots = [], r10)
        this.initModulesFromGroup(r10);
      else {
        this.roots.push(new h7());
        for (var o13 = 0; o13 < t18; ++o13)
          this.roots[0].add(this.modules[o13] = new u7(o13));
      }
      this.R = e22.length, e22.forEach(function(t19) {
        var e23 = i11.modules[n13.getSourceIndex(t19)], r11 = i11.modules[n13.getTargetIndex(t19)], o14 = n13.getType(t19);
        e23.outgoing.add(o14, r11), r11.incoming.add(o14, e23);
      });
    }
    return t17.prototype.initModulesFromGroup = function(t18) {
      var e22 = new h7();
      this.roots.push(e22);
      for (var n13 = 0; n13 < t18.leaves.length; ++n13) {
        var r10 = t18.leaves[n13], i11 = new u7(r10.id);
        this.modules[r10.id] = i11, e22.add(i11);
      }
      if (t18.groups)
        for (var o13 = 0; o13 < t18.groups.length; ++o13) {
          var s11 = t18.groups[o13], a10 = {};
          for (var p10 in s11)
            "leaves" !== p10 && "groups" !== p10 && s11.hasOwnProperty(p10) && (a10[p10] = s11[p10]);
          e22.add(new u7(-1 - o13, new c7(), new c7(), this.initModulesFromGroup(s11), a10));
        }
      return e22;
    }, t17.prototype.merge = function(t18, e22, n13) {
      void 0 === n13 && (n13 = 0);
      var r10 = t18.incoming.intersection(e22.incoming), i11 = t18.outgoing.intersection(e22.outgoing), o13 = new h7();
      o13.add(t18), o13.add(e22);
      var s11 = new u7(this.modules.length, i11, r10, o13);
      this.modules.push(s11);
      var a10 = function(n14, r11, i12) {
        n14.forAll(function(n15, o14) {
          n15.forAll(function(n16) {
            var a11 = n16[r11];
            a11.add(o14, s11), a11.remove(o14, t18), a11.remove(o14, e22), t18[i12].remove(o14, n16), e22[i12].remove(o14, n16);
          });
        });
      };
      return a10(i11, "incoming", "outgoing"), a10(r10, "outgoing", "incoming"), this.R -= r10.count() + i11.count(), this.roots[n13].remove(t18), this.roots[n13].remove(e22), this.roots[n13].add(s11), s11;
    }, t17.prototype.rootMerges = function(t18) {
      void 0 === t18 && (t18 = 0);
      for (var e22 = this.roots[t18].modules(), n13 = e22.length, r10 = new Array(n13 * (n13 - 1)), i11 = 0, o13 = 0, s11 = n13 - 1; o13 < s11; ++o13)
        for (var a10 = o13 + 1; a10 < n13; ++a10) {
          var u10 = e22[o13], h10 = e22[a10];
          r10[i11] = { id: i11, nEdges: this.nEdges(u10, h10), a: u10, b: h10 }, i11++;
        }
      return r10;
    }, t17.prototype.greedyMerge = function() {
      for (var t18 = 0; t18 < this.roots.length; ++t18)
        if (!(this.roots[t18].modules().length < 2)) {
          var e22 = this.rootMerges(t18).sort(function(t19, e23) {
            return t19.nEdges == e23.nEdges ? t19.id - e23.id : t19.nEdges - e23.nEdges;
          })[0];
          if (!(e22.nEdges >= this.R))
            return this.merge(e22.a, e22.b, t18), true;
        }
    }, t17.prototype.nEdges = function(t18, e22) {
      var n13 = t18.incoming.intersection(e22.incoming), r10 = t18.outgoing.intersection(e22.outgoing);
      return this.R - n13.count() - r10.count();
    }, t17.prototype.getGroupHierarchy = function(t18) {
      var e22 = this, n13 = [];
      return a6(this.roots[0], {}, n13), this.allEdges().forEach(function(r10) {
        var i11 = e22.modules[r10.source], s11 = e22.modules[r10.target];
        t18.push(new o8(void 0 === i11.gid ? r10.source : n13[i11.gid], void 0 === s11.gid ? r10.target : n13[s11.gid], r10.type));
      }), n13;
    }, t17.prototype.allEdges = function() {
      var e22 = [];
      return t17.getEdges(this.roots[0], e22), e22;
    }, t17.getEdges = function(e22, n13) {
      e22.forAll(function(e23) {
        e23.getEdges(n13), t17.getEdges(e23.children, n13);
      });
    }, t17;
  }();
  function a6(t17, e22, n13) {
    t17.forAll(function(t18) {
      if (t18.isLeaf())
        e22.leaves || (e22.leaves = []), e22.leaves.push(t18.id);
      else {
        var r10 = e22;
        if (t18.gid = n13.length, !t18.isIsland() || t18.isPredefined()) {
          if (r10 = { id: t18.gid }, t18.isPredefined())
            for (var i11 in t18.definition)
              r10[i11] = t18.definition[i11];
          e22.groups || (e22.groups = []), e22.groups.push(t18.gid), n13.push(r10);
        }
        a6(t18.children, r10, n13);
      }
    });
  }
  i7.Configuration = s7;
  var u7 = function() {
    function t17(t18, e22, n13, r10, i11) {
      void 0 === e22 && (e22 = new c7()), void 0 === n13 && (n13 = new c7()), void 0 === r10 && (r10 = new h7()), this.id = t18, this.outgoing = e22, this.incoming = n13, this.children = r10, this.definition = i11;
    }
    return t17.prototype.getEdges = function(t18) {
      var e22 = this;
      this.outgoing.forAll(function(n13, r10) {
        n13.forAll(function(n14) {
          t18.push(new o8(e22.id, n14.id, r10));
        });
      });
    }, t17.prototype.isLeaf = function() {
      return 0 === this.children.count();
    }, t17.prototype.isIsland = function() {
      return 0 === this.outgoing.count() && 0 === this.incoming.count();
    }, t17.prototype.isPredefined = function() {
      return void 0 !== this.definition;
    }, t17;
  }();
  i7.Module = u7;
  var h7 = function() {
    function t17() {
      this.table = {};
    }
    return t17.prototype.count = function() {
      return Object.keys(this.table).length;
    }, t17.prototype.intersection = function(e22) {
      var n13 = new t17();
      return n13.table = function(t18, e23) {
        var n14 = {};
        for (var r10 in t18)
          r10 in e23 && (n14[r10] = t18[r10]);
        return n14;
      }(this.table, e22.table), n13;
    }, t17.prototype.intersectionCount = function(t18) {
      return this.intersection(t18).count();
    }, t17.prototype.contains = function(t18) {
      return t18 in this.table;
    }, t17.prototype.add = function(t18) {
      this.table[t18.id] = t18;
    }, t17.prototype.remove = function(t18) {
      delete this.table[t18.id];
    }, t17.prototype.forAll = function(t18) {
      for (var e22 in this.table)
        t18(this.table[e22]);
    }, t17.prototype.modules = function() {
      var t18 = [];
      return this.forAll(function(e22) {
        e22.isPredefined() || t18.push(e22);
      }), t18;
    }, t17;
  }();
  i7.ModuleSet = h7;
  var c7 = function() {
    function t17() {
      this.sets = {}, this.n = 0;
    }
    return t17.prototype.count = function() {
      return this.n;
    }, t17.prototype.contains = function(t18) {
      var e22 = false;
      return this.forAllModules(function(n13) {
        e22 || n13.id != t18 || (e22 = true);
      }), e22;
    }, t17.prototype.add = function(t18, e22) {
      (t18 in this.sets ? this.sets[t18] : this.sets[t18] = new h7()).add(e22), ++this.n;
    }, t17.prototype.remove = function(t18, e22) {
      var n13 = this.sets[t18];
      n13.remove(e22), 0 === n13.count() && delete this.sets[t18], --this.n;
    }, t17.prototype.forAll = function(t18) {
      for (var e22 in this.sets)
        t18(this.sets[e22], Number(e22));
    }, t17.prototype.forAllModules = function(t18) {
      this.forAll(function(e22, n13) {
        return e22.forAll(t18);
      });
    }, t17.prototype.intersection = function(e22) {
      var n13 = new t17();
      return this.forAll(function(t18, r10) {
        if (r10 in e22.sets) {
          var i11 = t18.intersection(e22.sets[r10]), o13 = i11.count();
          o13 > 0 && (n13.sets[r10] = i11, n13.n += o13);
        }
      }), n13;
    }, t17;
  }();
  i7.LinkSets = c7, i7.getGroups = function(t17, e22, n13, r10) {
    for (var i11 = t17.length, o13 = new s7(i11, e22, n13, r10); o13.greedyMerge(); )
      ;
    var a10 = [], u10 = o13.getGroupHierarchy(a10);
    return a10.forEach(function(e23) {
      var n14 = function(n15) {
        var r11 = e23[n15];
        "number" == typeof r11 && (e23[n15] = t17[r11]);
      };
      n14("source"), n14("target");
    }), { groups: u10, powerEdges: a10 };
  };
  var p7 = {};
  function f7(t17, e22) {
    var n13 = {};
    for (var r10 in t17)
      n13[r10] = {};
    for (var r10 in e22)
      n13[r10] = {};
    return Object.keys(n13).length;
  }
  function l7(t17, e22) {
    var n13 = 0;
    for (var r10 in t17)
      void 0 !== e22[r10] && ++n13;
    return n13;
  }
  function d8(t17, e22, n13, r10) {
    var i11 = function(t18, e23) {
      var n14 = {}, r11 = function(t19, e24) {
        void 0 === n14[t19] && (n14[t19] = {}), n14[t19][e24] = {};
      };
      return t18.forEach(function(t19) {
        var n15 = e23.getSourceIndex(t19), i12 = e23.getTargetIndex(t19);
        r11(n15, i12), r11(i12, n15);
      }), n14;
    }(t17, r10);
    t17.forEach(function(t18) {
      var o13 = i11[r10.getSourceIndex(t18)], s11 = i11[r10.getTargetIndex(t18)];
      r10.setLength(t18, 1 + e22 * n13(o13, s11));
    });
  }
  function g7(t17, e22, n13) {
    var r10 = [], i11 = 0, o13 = [], s11 = [];
    function a10(t18) {
      t18.index = t18.lowlink = i11++, o13.push(t18), t18.onStack = true;
      for (var e23 = 0, n14 = t18.out; e23 < n14.length; e23++) {
        var r11 = n14[e23];
        void 0 === r11.index ? (a10(r11), t18.lowlink = Math.min(t18.lowlink, r11.lowlink)) : r11.onStack && (t18.lowlink = Math.min(t18.lowlink, r11.index));
      }
      if (t18.lowlink === t18.index) {
        for (var u11 = []; o13.length && ((r11 = o13.pop()).onStack = false, u11.push(r11), r11 !== t18); )
          ;
        s11.push(u11.map(function(t19) {
          return t19.id;
        }));
      }
    }
    for (var u10 = 0; u10 < t17; u10++)
      r10.push({ id: u10, out: [] });
    for (var h10 = 0, c10 = e22; h10 < c10.length; h10++) {
      var p10 = c10[h10], f11 = r10[n13.getSourceIndex(p10)], l11 = r10[n13.getTargetIndex(p10)];
      f11.out.push(l11);
    }
    for (var d12 = 0, g9 = r10; d12 < g9.length; d12++) {
      var v12 = g9[d12];
      void 0 === v12.index && a10(v12);
    }
    return s11;
  }
  Object.defineProperty(p7, "__esModule", { value: true }), p7.symmetricDiffLinkLengths = function(t17, e22, n13) {
    void 0 === n13 && (n13 = 1), d8(t17, n13, function(t18, e23) {
      return Math.sqrt(f7(t18, e23) - l7(t18, e23));
    }, e22);
  }, p7.jaccardLinkLengths = function(t17, e22, n13) {
    void 0 === n13 && (n13 = 1), d8(t17, n13, function(t18, e23) {
      return Math.min(Object.keys(t18).length, Object.keys(e23).length) < 1.1 ? 0 : l7(t18, e23) / f7(t18, e23);
    }, e22);
  }, p7.generateDirectedEdgeConstraints = function(t17, e22, n13, r10) {
    var i11 = g7(t17, e22, r10), o13 = {};
    i11.forEach(function(t18, e23) {
      return t18.forEach(function(t19) {
        return o13[t19] = e23;
      });
    });
    var s11 = [];
    return e22.forEach(function(t18) {
      var e23 = r10.getSourceIndex(t18), i12 = r10.getTargetIndex(t18);
      o13[e23] !== o13[i12] && s11.push({ axis: n13, left: e23, right: i12, gap: r10.getMinSeparation(t18) });
    }), s11;
  }, p7.stronglyConnectedComponents = g7;
  var v7 = {};
  Object.defineProperty(v7, "__esModule", { value: true });
  var y7 = function() {
    function t17() {
      this.locks = {};
    }
    return t17.prototype.add = function(t18, e22) {
      this.locks[t18] = e22;
    }, t17.prototype.clear = function() {
      this.locks = {};
    }, t17.prototype.isEmpty = function() {
      for (var t18 in this.locks)
        return false;
      return true;
    }, t17.prototype.apply = function(t18) {
      for (var e22 in this.locks)
        t18(Number(e22), this.locks[e22]);
    }, t17;
  }();
  v7.Locks = y7;
  var _6 = function() {
    function t17(t18, e22, n13) {
      void 0 === n13 && (n13 = null), this.D = e22, this.G = n13, this.threshold = 1e-4, this.numGridSnapNodes = 0, this.snapGridSize = 100, this.snapStrength = 1e3, this.scaleSnapByMaxH = false, this.random = new x7(), this.project = null, this.x = t18, this.k = t18.length;
      var r10 = this.n = t18[0].length;
      this.H = new Array(this.k), this.g = new Array(this.k), this.Hd = new Array(this.k), this.a = new Array(this.k), this.b = new Array(this.k), this.c = new Array(this.k), this.d = new Array(this.k), this.e = new Array(this.k), this.ia = new Array(this.k), this.ib = new Array(this.k), this.xtmp = new Array(this.k), this.locks = new y7(), this.minD = Number.MAX_VALUE;
      for (var i11, o13 = r10; o13--; )
        for (i11 = r10; --i11 > o13; ) {
          var s11 = e22[o13][i11];
          s11 > 0 && s11 < this.minD && (this.minD = s11);
        }
      for (this.minD === Number.MAX_VALUE && (this.minD = 1), o13 = this.k; o13--; ) {
        for (this.g[o13] = new Array(r10), this.H[o13] = new Array(r10), i11 = r10; i11--; )
          this.H[o13][i11] = new Array(r10);
        this.Hd[o13] = new Array(r10), this.a[o13] = new Array(r10), this.b[o13] = new Array(r10), this.c[o13] = new Array(r10), this.d[o13] = new Array(r10), this.e[o13] = new Array(r10), this.ia[o13] = new Array(r10), this.ib[o13] = new Array(r10), this.xtmp[o13] = new Array(r10);
      }
    }
    return t17.createSquareMatrix = function(t18, e22) {
      for (var n13 = new Array(t18), r10 = 0; r10 < t18; ++r10) {
        n13[r10] = new Array(t18);
        for (var i11 = 0; i11 < t18; ++i11)
          n13[r10][i11] = e22(r10, i11);
      }
      return n13;
    }, t17.prototype.offsetDir = function() {
      for (var t18 = this, e22 = new Array(this.k), n13 = 0, r10 = 0; r10 < this.k; ++r10) {
        var i11 = e22[r10] = this.random.getNextBetween(0.01, 1) - 0.5;
        n13 += i11 * i11;
      }
      return n13 = Math.sqrt(n13), e22.map(function(e23) {
        return e23 * (t18.minD / n13);
      });
    }, t17.prototype.computeDerivatives = function(t18) {
      var e22 = this, n13 = this.n;
      if (!(n13 < 1)) {
        for (var r10, i11 = new Array(this.k), o13 = new Array(this.k), s11 = new Array(this.k), a10 = 0, u10 = 0; u10 < n13; ++u10) {
          for (r10 = 0; r10 < this.k; ++r10)
            s11[r10] = this.g[r10][u10] = 0;
          for (var h10 = 0; h10 < n13; ++h10)
            if (u10 !== h10) {
              for (var c10 = n13; c10--; ) {
                var p10 = 0;
                for (r10 = 0; r10 < this.k; ++r10) {
                  var f11 = i11[r10] = t18[r10][u10] - t18[r10][h10];
                  p10 += o13[r10] = f11 * f11;
                }
                if (p10 > 1e-9)
                  break;
                var l11 = this.offsetDir();
                for (r10 = 0; r10 < this.k; ++r10)
                  t18[r10][h10] += l11[r10];
              }
              var d12 = Math.sqrt(p10), g9 = this.D[u10][h10], v12 = null != this.G ? this.G[u10][h10] : 1;
              if (v12 > 1 && d12 > g9 || !isFinite(g9))
                for (r10 = 0; r10 < this.k; ++r10)
                  this.H[r10][u10][h10] = 0;
              else {
                v12 > 1 && (v12 = 1);
                var y10 = g9 * g9, _7 = 2 * v12 * (d12 - g9) / (y10 * d12), x11 = d12 * d12 * d12, m12 = 2 * -v12 / (y10 * x11);
                for (isFinite(_7) || console.log(_7), r10 = 0; r10 < this.k; ++r10)
                  this.g[r10][u10] += i11[r10] * _7, s11[r10] -= this.H[r10][u10][h10] = m12 * (x11 + g9 * (o13[r10] - p10) + d12 * p10);
              }
            }
          for (r10 = 0; r10 < this.k; ++r10)
            a10 = Math.max(a10, this.H[r10][u10][u10] = s11[r10]);
        }
        var b11 = this.snapGridSize / 2, k10 = this.snapGridSize, w10 = this.snapStrength / (b11 * b11), E10 = this.numGridSnapNodes;
        for (u10 = 0; u10 < E10; ++u10)
          for (r10 = 0; r10 < this.k; ++r10) {
            var P10 = this.x[r10][u10], L10 = P10 / k10, M9 = L10 % 1, A10 = L10 - M9;
            -b11 < (f11 = Math.abs(M9) <= 0.5 ? P10 - A10 * k10 : P10 > 0 ? P10 - (A10 + 1) * k10 : P10 - (A10 - 1) * k10) && f11 <= b11 && (this.scaleSnapByMaxH ? (this.g[r10][u10] += a10 * w10 * f11, this.H[r10][u10][u10] += a10 * w10) : (this.g[r10][u10] += w10 * f11, this.H[r10][u10][u10] += w10));
          }
        this.locks.isEmpty() || this.locks.apply(function(n14, i12) {
          for (r10 = 0; r10 < e22.k; ++r10)
            e22.H[r10][n14][n14] += a10, e22.g[r10][n14] -= a10 * (i12[r10] - t18[r10][n14]);
        });
      }
    }, t17.dotProd = function(t18, e22) {
      for (var n13 = 0, r10 = t18.length; r10--; )
        n13 += t18[r10] * e22[r10];
      return n13;
    }, t17.rightMultiply = function(e22, n13, r10) {
      for (var i11 = e22.length; i11--; )
        r10[i11] = t17.dotProd(e22[i11], n13);
    }, t17.prototype.computeStepSize = function(e22) {
      for (var n13 = 0, r10 = 0, i11 = 0; i11 < this.k; ++i11)
        n13 += t17.dotProd(this.g[i11], e22[i11]), t17.rightMultiply(this.H[i11], e22[i11], this.Hd[i11]), r10 += t17.dotProd(e22[i11], this.Hd[i11]);
      return 0 !== r10 && isFinite(r10) ? 1 * n13 / r10 : 0;
    }, t17.prototype.reduceStress = function() {
      this.computeDerivatives(this.x);
      for (var t18 = this.computeStepSize(this.g), e22 = 0; e22 < this.k; ++e22)
        this.takeDescentStep(this.x[e22], this.g[e22], t18);
      return this.computeStress();
    }, t17.copy = function(t18, e22) {
      for (var n13 = t18.length, r10 = e22[0].length, i11 = 0; i11 < n13; ++i11)
        for (var o13 = 0; o13 < r10; ++o13)
          e22[i11][o13] = t18[i11][o13];
    }, t17.prototype.stepAndProject = function(e22, n13, r10, i11) {
      t17.copy(e22, n13), this.takeDescentStep(n13[0], r10[0], i11), this.project && this.project[0](e22[0], e22[1], n13[0]), this.takeDescentStep(n13[1], r10[1], i11), this.project && this.project[1](n13[0], e22[1], n13[1]);
      for (var o13 = 2; o13 < this.k; o13++)
        this.takeDescentStep(n13[o13], r10[o13], i11);
    }, t17.mApply = function(t18, e22, n13) {
      for (var r10 = t18; r10-- > 0; )
        for (var i11 = e22; i11-- > 0; )
          n13(r10, i11);
    }, t17.prototype.matrixApply = function(e22) {
      t17.mApply(this.k, this.n, e22);
    }, t17.prototype.computeNextPosition = function(t18, e22) {
      var n13 = this;
      this.computeDerivatives(t18);
      var r10 = this.computeStepSize(this.g);
      if (this.stepAndProject(t18, e22, this.g, r10), this.project) {
        this.matrixApply(function(r11, i12) {
          return n13.e[r11][i12] = t18[r11][i12] - e22[r11][i12];
        });
        var i11 = this.computeStepSize(this.e);
        i11 = Math.max(0.2, Math.min(i11, 1)), this.stepAndProject(t18, e22, this.e, i11);
      }
    }, t17.prototype.run = function(t18) {
      for (var e22 = Number.MAX_VALUE, n13 = false; !n13 && t18-- > 0; ) {
        var r10 = this.rungeKutta();
        n13 = Math.abs(e22 / r10 - 1) < this.threshold, e22 = r10;
      }
      return e22;
    }, t17.prototype.rungeKutta = function() {
      var e22 = this;
      this.computeNextPosition(this.x, this.a), t17.mid(this.x, this.a, this.ia), this.computeNextPosition(this.ia, this.b), t17.mid(this.x, this.b, this.ib), this.computeNextPosition(this.ib, this.c), this.computeNextPosition(this.c, this.d);
      var n13 = 0;
      return this.matrixApply(function(t18, r10) {
        var i11 = (e22.a[t18][r10] + 2 * e22.b[t18][r10] + 2 * e22.c[t18][r10] + e22.d[t18][r10]) / 6, o13 = e22.x[t18][r10] - i11;
        n13 += o13 * o13, e22.x[t18][r10] = i11;
      }), n13;
    }, t17.mid = function(e22, n13, r10) {
      t17.mApply(e22.length, e22[0].length, function(t18, i11) {
        return r10[t18][i11] = e22[t18][i11] + (n13[t18][i11] - e22[t18][i11]) / 2;
      });
    }, t17.prototype.takeDescentStep = function(t18, e22, n13) {
      for (var r10 = 0; r10 < this.n; ++r10)
        t18[r10] = t18[r10] - n13 * e22[r10];
    }, t17.prototype.computeStress = function() {
      for (var t18 = 0, e22 = 0, n13 = this.n - 1; e22 < n13; ++e22)
        for (var r10 = e22 + 1, i11 = this.n; r10 < i11; ++r10) {
          for (var o13 = 0, s11 = 0; s11 < this.k; ++s11) {
            var a10 = this.x[s11][e22] - this.x[s11][r10];
            o13 += a10 * a10;
          }
          o13 = Math.sqrt(o13);
          var u10 = this.D[e22][r10];
          if (isFinite(u10)) {
            var h10 = u10 - o13;
            t18 += h10 * h10 / (u10 * u10);
          }
        }
      return t18;
    }, t17.zeroDistance = 1e-10, t17;
  }();
  v7.Descent = _6;
  var x7 = function() {
    function t17(t18) {
      void 0 === t18 && (t18 = 1), this.seed = t18, this.a = 214013, this.c = 2531011, this.m = 2147483648, this.range = 32767;
    }
    return t17.prototype.getNext = function() {
      return this.seed = (this.seed * this.a + this.c) % this.m, (this.seed >> 16) / this.range;
    }, t17.prototype.getNextBetween = function(t18, e22) {
      return t18 + this.getNext() * (e22 - t18);
    }, t17;
  }();
  v7.PseudoRandom = x7;
  var m8 = {};
  var b7 = {};
  Object.defineProperty(b7, "__esModule", { value: true });
  var k6 = function() {
    function t17(t18) {
      this.scale = t18, this.AB = 0, this.AD = 0, this.A2 = 0;
    }
    return t17.prototype.addVariable = function(t18) {
      var e22 = this.scale / t18.scale, n13 = t18.offset / t18.scale, r10 = t18.weight;
      this.AB += r10 * e22 * n13, this.AD += r10 * e22 * t18.desiredPosition, this.A2 += r10 * e22 * e22;
    }, t17.prototype.getPosn = function() {
      return (this.AD - this.AB) / this.A2;
    }, t17;
  }();
  b7.PositionStats = k6;
  var w7 = function() {
    function t17(t18, e22, n13, r10) {
      void 0 === r10 && (r10 = false), this.left = t18, this.right = e22, this.gap = n13, this.equality = r10, this.active = false, this.unsatisfiable = false, this.left = t18, this.right = e22, this.gap = n13, this.equality = r10;
    }
    return t17.prototype.slack = function() {
      return this.unsatisfiable ? Number.MAX_VALUE : this.right.scale * this.right.position() - this.gap - this.left.scale * this.left.position();
    }, t17;
  }();
  b7.Constraint = w7;
  var E7 = function() {
    function t17(t18, e22, n13) {
      void 0 === e22 && (e22 = 1), void 0 === n13 && (n13 = 1), this.desiredPosition = t18, this.weight = e22, this.scale = n13, this.offset = 0;
    }
    return t17.prototype.dfdv = function() {
      return 2 * this.weight * (this.position() - this.desiredPosition);
    }, t17.prototype.position = function() {
      return (this.block.ps.scale * this.block.posn + this.offset) / this.scale;
    }, t17.prototype.visitNeighbours = function(t18, e22) {
      var n13 = function(n14, r10) {
        return n14.active && t18 !== r10 && e22(n14, r10);
      };
      this.cOut.forEach(function(t19) {
        return n13(t19, t19.right);
      }), this.cIn.forEach(function(t19) {
        return n13(t19, t19.left);
      });
    }, t17;
  }();
  b7.Variable = E7;
  var P7 = function() {
    function t17(t18) {
      this.vars = [], t18.offset = 0, this.ps = new k6(t18.scale), this.addVariable(t18);
    }
    return t17.prototype.addVariable = function(t18) {
      t18.block = this, this.vars.push(t18), this.ps.addVariable(t18), this.posn = this.ps.getPosn();
    }, t17.prototype.updateWeightedPosition = function() {
      this.ps.AB = this.ps.AD = this.ps.A2 = 0;
      for (var t18 = 0, e22 = this.vars.length; t18 < e22; ++t18)
        this.ps.addVariable(this.vars[t18]);
      this.posn = this.ps.getPosn();
    }, t17.prototype.compute_lm = function(t18, e22, n13) {
      var r10 = this, i11 = t18.dfdv();
      return t18.visitNeighbours(e22, function(e23, o13) {
        var s11 = r10.compute_lm(o13, t18, n13);
        o13 === e23.right ? (i11 += s11 * e23.left.scale, e23.lm = s11) : (i11 += s11 * e23.right.scale, e23.lm = -s11), n13(e23);
      }), i11 / t18.scale;
    }, t17.prototype.populateSplitBlock = function(t18, e22) {
      var n13 = this;
      t18.visitNeighbours(e22, function(e23, r10) {
        r10.offset = t18.offset + (r10 === e23.right ? e23.gap : -e23.gap), n13.addVariable(r10), n13.populateSplitBlock(r10, t18);
      });
    }, t17.prototype.traverse = function(t18, e22, n13, r10) {
      var i11 = this;
      void 0 === n13 && (n13 = this.vars[0]), void 0 === r10 && (r10 = null), n13.visitNeighbours(r10, function(r11, o13) {
        e22.push(t18(r11)), i11.traverse(t18, e22, o13, n13);
      });
    }, t17.prototype.findMinLM = function() {
      var t18 = null;
      return this.compute_lm(this.vars[0], null, function(e22) {
        !e22.equality && (null === t18 || e22.lm < t18.lm) && (t18 = e22);
      }), t18;
    }, t17.prototype.findMinLMBetween = function(t18, e22) {
      this.compute_lm(t18, null, function() {
      });
      var n13 = null;
      return this.findPath(t18, null, e22, function(t19, e23) {
        !t19.equality && t19.right === e23 && (null === n13 || t19.lm < n13.lm) && (n13 = t19);
      }), n13;
    }, t17.prototype.findPath = function(t18, e22, n13, r10) {
      var i11 = this, o13 = false;
      return t18.visitNeighbours(e22, function(e23, s11) {
        o13 || s11 !== n13 && !i11.findPath(s11, t18, n13, r10) || (o13 = true, r10(e23, s11));
      }), o13;
    }, t17.prototype.isActiveDirectedPathBetween = function(t18, e22) {
      if (t18 === e22)
        return true;
      for (var n13 = t18.cOut.length; n13--; ) {
        var r10 = t18.cOut[n13];
        if (r10.active && this.isActiveDirectedPathBetween(r10.right, e22))
          return true;
      }
      return false;
    }, t17.split = function(e22) {
      return e22.active = false, [t17.createSplitBlock(e22.left), t17.createSplitBlock(e22.right)];
    }, t17.createSplitBlock = function(e22) {
      var n13 = new t17(e22);
      return n13.populateSplitBlock(e22, null), n13;
    }, t17.prototype.splitBetween = function(e22, n13) {
      var r10 = this.findMinLMBetween(e22, n13);
      if (null !== r10) {
        var i11 = t17.split(r10);
        return { constraint: r10, lb: i11[0], rb: i11[1] };
      }
      return null;
    }, t17.prototype.mergeAcross = function(t18, e22, n13) {
      e22.active = true;
      for (var r10 = 0, i11 = t18.vars.length; r10 < i11; ++r10) {
        var o13 = t18.vars[r10];
        o13.offset += n13, this.addVariable(o13);
      }
      this.posn = this.ps.getPosn();
    }, t17.prototype.cost = function() {
      for (var t18 = 0, e22 = this.vars.length; e22--; ) {
        var n13 = this.vars[e22], r10 = n13.position() - n13.desiredPosition;
        t18 += r10 * r10 * n13.weight;
      }
      return t18;
    }, t17;
  }();
  b7.Block = P7;
  var L6 = function() {
    function t17(t18) {
      this.vs = t18;
      var e22 = t18.length;
      for (this.list = new Array(e22); e22--; ) {
        var n13 = new P7(t18[e22]);
        this.list[e22] = n13, n13.blockInd = e22;
      }
    }
    return t17.prototype.cost = function() {
      for (var t18 = 0, e22 = this.list.length; e22--; )
        t18 += this.list[e22].cost();
      return t18;
    }, t17.prototype.insert = function(t18) {
      t18.blockInd = this.list.length, this.list.push(t18);
    }, t17.prototype.remove = function(t18) {
      var e22 = this.list.length - 1, n13 = this.list[e22];
      this.list.length = e22, t18 !== n13 && (this.list[t18.blockInd] = n13, n13.blockInd = t18.blockInd);
    }, t17.prototype.merge = function(t18) {
      var e22 = t18.left.block, n13 = t18.right.block, r10 = t18.right.offset - t18.left.offset - t18.gap;
      e22.vars.length < n13.vars.length ? (n13.mergeAcross(e22, t18, r10), this.remove(e22)) : (e22.mergeAcross(n13, t18, -r10), this.remove(n13));
    }, t17.prototype.forEach = function(t18) {
      this.list.forEach(t18);
    }, t17.prototype.updateBlockPositions = function() {
      this.list.forEach(function(t18) {
        return t18.updateWeightedPosition();
      });
    }, t17.prototype.split = function(t18) {
      var e22 = this;
      this.updateBlockPositions(), this.list.forEach(function(n13) {
        var r10 = n13.findMinLM();
        null !== r10 && r10.lm < M7.LAGRANGIAN_TOLERANCE && (n13 = r10.left.block, P7.split(r10).forEach(function(t19) {
          return e22.insert(t19);
        }), e22.remove(n13), t18.push(r10));
      });
    }, t17;
  }();
  b7.Blocks = L6;
  var M7 = function() {
    function t17(t18, e22) {
      this.vs = t18, this.cs = e22, this.vs = t18, t18.forEach(function(t19) {
        t19.cIn = [], t19.cOut = [];
      }), this.cs = e22, e22.forEach(function(t19) {
        t19.left.cOut.push(t19), t19.right.cIn.push(t19);
      }), this.inactive = e22.map(function(t19) {
        return t19.active = false, t19;
      }), this.bs = null;
    }
    return t17.prototype.cost = function() {
      return this.bs.cost();
    }, t17.prototype.setStartingPositions = function(t18) {
      this.inactive = this.cs.map(function(t19) {
        return t19.active = false, t19;
      }), this.bs = new L6(this.vs), this.bs.forEach(function(e22, n13) {
        return e22.posn = t18[n13];
      });
    }, t17.prototype.setDesiredPositions = function(t18) {
      this.vs.forEach(function(e22, n13) {
        return e22.desiredPosition = t18[n13];
      });
    }, t17.prototype.mostViolated = function() {
      for (var e22 = Number.MAX_VALUE, n13 = null, r10 = this.inactive, i11 = r10.length, o13 = i11, s11 = 0; s11 < i11; ++s11) {
        var a10 = r10[s11];
        if (!a10.unsatisfiable) {
          var u10 = a10.slack();
          if ((a10.equality || u10 < e22) && (e22 = u10, n13 = a10, o13 = s11, a10.equality))
            break;
        }
      }
      return o13 !== i11 && (e22 < t17.ZERO_UPPERBOUND && !n13.active || n13.equality) && (r10[o13] = r10[i11 - 1], r10.length = i11 - 1), n13;
    }, t17.prototype.satisfy = function() {
      null == this.bs && (this.bs = new L6(this.vs)), this.bs.split(this.inactive);
      for (var e22 = null; (e22 = this.mostViolated()) && (e22.equality || e22.slack() < t17.ZERO_UPPERBOUND && !e22.active); ) {
        var n13 = e22.left.block;
        if (n13 !== e22.right.block)
          this.bs.merge(e22);
        else {
          if (n13.isActiveDirectedPathBetween(e22.right, e22.left)) {
            e22.unsatisfiable = true;
            continue;
          }
          var r10 = n13.splitBetween(e22.left, e22.right);
          if (null === r10) {
            e22.unsatisfiable = true;
            continue;
          }
          this.bs.insert(r10.lb), this.bs.insert(r10.rb), this.bs.remove(n13), this.inactive.push(r10.constraint), e22.slack() >= 0 ? this.inactive.push(e22) : this.bs.merge(e22);
        }
      }
    }, t17.prototype.solve = function() {
      this.satisfy();
      for (var t18 = Number.MAX_VALUE, e22 = this.bs.cost(); Math.abs(t18 - e22) > 1e-4; )
        this.satisfy(), t18 = e22, e22 = this.bs.cost();
      return e22;
    }, t17.LAGRANGIAN_TOLERANCE = -1e-4, t17.ZERO_UPPERBOUND = -1e-10, t17;
  }();
  b7.Solver = M7, b7.removeOverlapInOneDimension = function(t17, e22, n13) {
    for (var r10 = t17.map(function(t18) {
      return new E7(t18.desiredCenter);
    }), i11 = [], o13 = t17.length, s11 = 0; s11 < o13 - 1; s11++) {
      var a10 = t17[s11], u10 = t17[s11 + 1];
      i11.push(new w7(r10[s11], r10[s11 + 1], (a10.size + u10.size) / 2));
    }
    var h10 = r10[0], c10 = r10[o13 - 1], p10 = t17[0].size / 2, f11 = t17[o13 - 1].size / 2, l11 = null, d12 = null;
    return e22 && (l11 = new E7(e22, 1e3 * h10.weight), r10.push(l11), i11.push(new w7(l11, h10, p10))), n13 && (d12 = new E7(n13, 1e3 * c10.weight), r10.push(d12), i11.push(new w7(c10, d12, f11))), new M7(r10, i11).solve(), { newCenters: r10.slice(0, t17.length).map(function(t18) {
      return t18.position();
    }), lowerBound: l11 ? l11.position() : h10.position() - p10, upperBound: d12 ? d12.position() : c10.position() + f11 };
  };
  var A7;
  var S7 = {};
  var O7 = t11 && t11.__extends || (A7 = function(t17, e22) {
    return A7 = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function(t18, e23) {
      t18.__proto__ = e23;
    } || function(t18, e23) {
      for (var n13 in e23)
        e23.hasOwnProperty(n13) && (t18[n13] = e23[n13]);
    }, A7(t17, e22);
  }, function(t17, e22) {
    function n13() {
      this.constructor = t17;
    }
    A7(t17, e22), t17.prototype = null === e22 ? Object.create(e22) : (n13.prototype = e22.prototype, new n13());
  });
  Object.defineProperty(S7, "__esModule", { value: true });
  var C6 = function() {
    function t17() {
      this.findIter = function(t18) {
        for (var e22 = this._root, n13 = this.iterator(); null !== e22; ) {
          var r10 = this._comparator(t18, e22.data);
          if (0 === r10)
            return n13._cursor = e22, n13;
          n13._ancestors.push(e22), e22 = e22.get_child(r10 > 0);
        }
        return null;
      };
    }
    return t17.prototype.clear = function() {
      this._root = null, this.size = 0;
    }, t17.prototype.find = function(t18) {
      for (var e22 = this._root; null !== e22; ) {
        var n13 = this._comparator(t18, e22.data);
        if (0 === n13)
          return e22.data;
        e22 = e22.get_child(n13 > 0);
      }
      return null;
    }, t17.prototype.lowerBound = function(t18) {
      return this._bound(t18, this._comparator);
    }, t17.prototype.upperBound = function(t18) {
      var e22 = this._comparator;
      return this._bound(t18, function(t19, n13) {
        return e22(n13, t19);
      });
    }, t17.prototype.min = function() {
      var t18 = this._root;
      if (null === t18)
        return null;
      for (; null !== t18.left; )
        t18 = t18.left;
      return t18.data;
    }, t17.prototype.max = function() {
      var t18 = this._root;
      if (null === t18)
        return null;
      for (; null !== t18.right; )
        t18 = t18.right;
      return t18.data;
    }, t17.prototype.iterator = function() {
      return new N7(this);
    }, t17.prototype.each = function(t18) {
      for (var e22, n13 = this.iterator(); null !== (e22 = n13.next()); )
        t18(e22);
    }, t17.prototype.reach = function(t18) {
      for (var e22, n13 = this.iterator(); null !== (e22 = n13.prev()); )
        t18(e22);
    }, t17.prototype._bound = function(t18, e22) {
      for (var n13 = this._root, r10 = this.iterator(); null !== n13; ) {
        var i11 = this._comparator(t18, n13.data);
        if (0 === i11)
          return r10._cursor = n13, r10;
        r10._ancestors.push(n13), n13 = n13.get_child(i11 > 0);
      }
      for (var o13 = r10._ancestors.length - 1; o13 >= 0; --o13)
        if (e22(t18, (n13 = r10._ancestors[o13]).data) > 0)
          return r10._cursor = n13, r10._ancestors.length = o13, r10;
      return r10._ancestors.length = 0, r10;
    }, t17;
  }();
  S7.TreeBase = C6;
  var N7 = function() {
    function t17(t18) {
      this._tree = t18, this._ancestors = [], this._cursor = null;
    }
    return t17.prototype.data = function() {
      return null !== this._cursor ? this._cursor.data : null;
    }, t17.prototype.next = function() {
      if (null === this._cursor) {
        var t18 = this._tree._root;
        null !== t18 && this._minNode(t18);
      } else {
        var e22;
        if (null === this._cursor.right)
          do {
            if (e22 = this._cursor, !this._ancestors.length) {
              this._cursor = null;
              break;
            }
            this._cursor = this._ancestors.pop();
          } while (this._cursor.right === e22);
        else
          this._ancestors.push(this._cursor), this._minNode(this._cursor.right);
      }
      return null !== this._cursor ? this._cursor.data : null;
    }, t17.prototype.prev = function() {
      if (null === this._cursor) {
        var t18 = this._tree._root;
        null !== t18 && this._maxNode(t18);
      } else {
        var e22;
        if (null === this._cursor.left)
          do {
            if (e22 = this._cursor, !this._ancestors.length) {
              this._cursor = null;
              break;
            }
            this._cursor = this._ancestors.pop();
          } while (this._cursor.left === e22);
        else
          this._ancestors.push(this._cursor), this._maxNode(this._cursor.left);
      }
      return null !== this._cursor ? this._cursor.data : null;
    }, t17.prototype._minNode = function(t18) {
      for (; null !== t18.left; )
        this._ancestors.push(t18), t18 = t18.left;
      this._cursor = t18;
    }, t17.prototype._maxNode = function(t18) {
      for (; null !== t18.right; )
        this._ancestors.push(t18), t18 = t18.right;
      this._cursor = t18;
    }, t17;
  }();
  S7.Iterator = N7;
  var I7 = function() {
    function t17(t18) {
      this.data = t18, this.left = null, this.right = null, this.red = true;
    }
    return t17.prototype.get_child = function(t18) {
      return t18 ? this.right : this.left;
    }, t17.prototype.set_child = function(t18, e22) {
      t18 ? this.right = e22 : this.left = e22;
    }, t17;
  }();
  var T7 = function(t17) {
    function e22(e23) {
      var n13 = t17.call(this) || this;
      return n13._root = null, n13._comparator = e23, n13.size = 0, n13;
    }
    return O7(e22, t17), e22.prototype.insert = function(t18) {
      var n13 = false;
      if (null === this._root)
        this._root = new I7(t18), n13 = true, this.size++;
      else {
        var r10 = new I7(void 0), i11 = false, o13 = false, s11 = null, a10 = r10, u10 = null, h10 = this._root;
        for (a10.right = this._root; ; ) {
          if (null === h10 ? (h10 = new I7(t18), u10.set_child(i11, h10), n13 = true, this.size++) : e22.is_red(h10.left) && e22.is_red(h10.right) && (h10.red = true, h10.left.red = false, h10.right.red = false), e22.is_red(h10) && e22.is_red(u10)) {
            var c10 = a10.right === s11;
            h10 === u10.get_child(o13) ? a10.set_child(c10, e22.single_rotate(s11, !o13)) : a10.set_child(c10, e22.double_rotate(s11, !o13));
          }
          var p10 = this._comparator(h10.data, t18);
          if (0 === p10)
            break;
          o13 = i11, i11 = p10 < 0, null !== s11 && (a10 = s11), s11 = u10, u10 = h10, h10 = h10.get_child(i11);
        }
        this._root = r10.right;
      }
      return this._root.red = false, n13;
    }, e22.prototype.remove = function(t18) {
      if (null === this._root)
        return false;
      var n13 = new I7(void 0), r10 = n13;
      r10.right = this._root;
      for (var i11 = null, o13 = null, s11 = null, a10 = true; null !== r10.get_child(a10); ) {
        var u10 = a10;
        o13 = i11, i11 = r10, r10 = r10.get_child(a10);
        var h10 = this._comparator(t18, r10.data);
        if (a10 = h10 > 0, 0 === h10 && (s11 = r10), !e22.is_red(r10) && !e22.is_red(r10.get_child(a10))) {
          if (e22.is_red(r10.get_child(!a10))) {
            var c10 = e22.single_rotate(r10, a10);
            i11.set_child(u10, c10), i11 = c10;
          } else if (!e22.is_red(r10.get_child(!a10))) {
            var p10 = i11.get_child(!u10);
            if (null !== p10)
              if (e22.is_red(p10.get_child(!u10)) || e22.is_red(p10.get_child(u10))) {
                var f11 = o13.right === i11;
                e22.is_red(p10.get_child(u10)) ? o13.set_child(f11, e22.double_rotate(i11, u10)) : e22.is_red(p10.get_child(!u10)) && o13.set_child(f11, e22.single_rotate(i11, u10));
                var l11 = o13.get_child(f11);
                l11.red = true, r10.red = true, l11.left.red = false, l11.right.red = false;
              } else
                i11.red = false, p10.red = true, r10.red = true;
          }
        }
      }
      return null !== s11 && (s11.data = r10.data, i11.set_child(i11.right === r10, r10.get_child(null === r10.left)), this.size--), this._root = n13.right, null !== this._root && (this._root.red = false), null !== s11;
    }, e22.is_red = function(t18) {
      return null !== t18 && t18.red;
    }, e22.single_rotate = function(t18, e23) {
      var n13 = t18.get_child(!e23);
      return t18.set_child(!e23, n13.get_child(e23)), n13.set_child(e23, t18), t18.red = true, n13.red = false, n13;
    }, e22.double_rotate = function(t18, n13) {
      return t18.set_child(!n13, e22.single_rotate(t18.get_child(!n13), !n13)), e22.single_rotate(t18, n13);
    }, e22;
  }(C6);
  S7.RBTree = T7;
  var G5 = t11 && t11.__extends || function() {
    var t17 = function(e22, n13) {
      return t17 = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function(t18, e23) {
        t18.__proto__ = e23;
      } || function(t18, e23) {
        for (var n14 in e23)
          e23.hasOwnProperty(n14) && (t18[n14] = e23[n14]);
      }, t17(e22, n13);
    };
    return function(e22, n13) {
      function r10() {
        this.constructor = e22;
      }
      t17(e22, n13), e22.prototype = null === n13 ? Object.create(n13) : (r10.prototype = n13.prototype, new r10());
    };
  }();
  Object.defineProperty(m8, "__esModule", { value: true });
  var V6 = b7;
  var D6 = S7;
  function j7(t17) {
    return t17.bounds = void 0 !== t17.leaves ? t17.leaves.reduce(function(t18, e22) {
      return e22.bounds.union(t18);
    }, B5.empty()) : B5.empty(), void 0 !== t17.groups && (t17.bounds = t17.groups.reduce(function(t18, e22) {
      return j7(e22).union(t18);
    }, t17.bounds)), t17.bounds = t17.bounds.inflate(t17.padding), t17.bounds;
  }
  m8.computeGroupBounds = j7;
  var B5 = function() {
    function t17(t18, e22, n13, r10) {
      this.x = t18, this.X = e22, this.y = n13, this.Y = r10;
    }
    return t17.empty = function() {
      return new t17(Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY);
    }, t17.prototype.cx = function() {
      return (this.x + this.X) / 2;
    }, t17.prototype.cy = function() {
      return (this.y + this.Y) / 2;
    }, t17.prototype.overlapX = function(t18) {
      var e22 = this.cx(), n13 = t18.cx();
      return e22 <= n13 && t18.x < this.X ? this.X - t18.x : n13 <= e22 && this.x < t18.X ? t18.X - this.x : 0;
    }, t17.prototype.overlapY = function(t18) {
      var e22 = this.cy(), n13 = t18.cy();
      return e22 <= n13 && t18.y < this.Y ? this.Y - t18.y : n13 <= e22 && this.y < t18.Y ? t18.Y - this.y : 0;
    }, t17.prototype.setXCentre = function(t18) {
      var e22 = t18 - this.cx();
      this.x += e22, this.X += e22;
    }, t17.prototype.setYCentre = function(t18) {
      var e22 = t18 - this.cy();
      this.y += e22, this.Y += e22;
    }, t17.prototype.width = function() {
      return this.X - this.x;
    }, t17.prototype.height = function() {
      return this.Y - this.y;
    }, t17.prototype.union = function(e22) {
      return new t17(Math.min(this.x, e22.x), Math.max(this.X, e22.X), Math.min(this.y, e22.y), Math.max(this.Y, e22.Y));
    }, t17.prototype.lineIntersections = function(e22, n13, r10, i11) {
      for (var o13 = [[this.x, this.y, this.X, this.y], [this.X, this.y, this.X, this.Y], [this.X, this.Y, this.x, this.Y], [this.x, this.Y, this.x, this.y]], s11 = [], a10 = 0; a10 < 4; ++a10) {
        var u10 = t17.lineIntersection(e22, n13, r10, i11, o13[a10][0], o13[a10][1], o13[a10][2], o13[a10][3]);
        null !== u10 && s11.push({ x: u10.x, y: u10.y });
      }
      return s11;
    }, t17.prototype.rayIntersection = function(t18, e22) {
      var n13 = this.lineIntersections(this.cx(), this.cy(), t18, e22);
      return n13.length > 0 ? n13[0] : null;
    }, t17.prototype.vertices = function() {
      return [{ x: this.x, y: this.y }, { x: this.X, y: this.y }, { x: this.X, y: this.Y }, { x: this.x, y: this.Y }];
    }, t17.lineIntersection = function(t18, e22, n13, r10, i11, o13, s11, a10) {
      var u10 = n13 - t18, h10 = s11 - i11, c10 = r10 - e22, p10 = a10 - o13, f11 = p10 * u10 - h10 * c10;
      if (0 == f11)
        return null;
      var l11 = t18 - i11, d12 = e22 - o13, g9 = (h10 * d12 - p10 * l11) / f11, v12 = (u10 * d12 - c10 * l11) / f11;
      return g9 >= 0 && g9 <= 1 && v12 >= 0 && v12 <= 1 ? { x: t18 + g9 * u10, y: e22 + g9 * c10 } : null;
    }, t17.prototype.inflate = function(e22) {
      return new t17(this.x - e22, this.X + e22, this.y - e22, this.Y + e22);
    }, t17;
  }();
  m8.Rectangle = B5, m8.makeEdgeBetween = function(t17, e22, n13) {
    var r10 = t17.rayIntersection(e22.cx(), e22.cy()) || { x: t17.cx(), y: t17.cy() }, i11 = e22.rayIntersection(t17.cx(), t17.cy()) || { x: e22.cx(), y: e22.cy() }, o13 = i11.x - r10.x, s11 = i11.y - r10.y, a10 = Math.sqrt(o13 * o13 + s11 * s11), u10 = a10 - n13;
    return { sourceIntersection: r10, targetIntersection: i11, arrowStart: { x: r10.x + u10 * o13 / a10, y: r10.y + u10 * s11 / a10 } };
  }, m8.makeEdgeTo = function(t17, e22, n13) {
    var r10 = e22.rayIntersection(t17.x, t17.y);
    r10 || (r10 = { x: e22.cx(), y: e22.cy() });
    var i11 = r10.x - t17.x, o13 = r10.y - t17.y, s11 = Math.sqrt(i11 * i11 + o13 * o13);
    return { x: r10.x - n13 * i11 / s11, y: r10.y - n13 * o13 / s11 };
  };
  var R5 = function(t17, e22, n13) {
    this.v = t17, this.r = e22, this.pos = n13, this.prev = Y5(), this.next = Y5();
  };
  var X5 = function(t17, e22, n13) {
    this.isOpen = t17, this.v = e22, this.pos = n13;
  };
  function z6(t17, e22) {
    return t17.pos > e22.pos ? 1 : t17.pos < e22.pos || t17.isOpen ? -1 : e22.isOpen ? 1 : 0;
  }
  function Y5() {
    return new D6.RBTree(function(t17, e22) {
      return t17.pos - e22.pos;
    });
  }
  var q6 = { getCentre: function(t17) {
    return t17.cx();
  }, getOpen: function(t17) {
    return t17.y;
  }, getClose: function(t17) {
    return t17.Y;
  }, getSize: function(t17) {
    return t17.width();
  }, makeRect: function(t17, e22, n13, r10) {
    return new B5(n13 - r10 / 2, n13 + r10 / 2, t17, e22);
  }, findNeighbours: function(t17, e22) {
    var n13 = function(n14, r10) {
      for (var i11, o13 = e22.findIter(t17); null !== (i11 = o13[n14]()); ) {
        var s11 = i11.r.overlapX(t17.r);
        if ((s11 <= 0 || s11 <= i11.r.overlapY(t17.r)) && (t17[n14].insert(i11), i11[r10].insert(t17)), s11 <= 0)
          break;
      }
    };
    n13("next", "prev"), n13("prev", "next");
  } };
  var F7 = { getCentre: function(t17) {
    return t17.cy();
  }, getOpen: function(t17) {
    return t17.x;
  }, getClose: function(t17) {
    return t17.X;
  }, getSize: function(t17) {
    return t17.height();
  }, makeRect: function(t17, e22, n13, r10) {
    return new B5(t17, e22, n13 - r10 / 2, n13 + r10 / 2);
  }, findNeighbours: function(t17, e22) {
    var n13 = function(n14, r10) {
      var i11 = e22.findIter(t17)[n14]();
      null !== i11 && i11.r.overlapX(t17.r) > 0 && (t17[n14].insert(i11), i11[r10].insert(t17));
    };
    n13("next", "prev"), n13("prev", "next");
  } };
  function H5(t17, e22, n13, r10) {
    void 0 === r10 && (r10 = false);
    var i11 = t17.padding, o13 = void 0 !== t17.groups ? t17.groups.length : 0, s11 = void 0 !== t17.leaves ? t17.leaves.length : 0, a10 = o13 ? t17.groups.reduce(function(t18, r11) {
      return t18.concat(H5(r11, e22, n13, true));
    }, []) : [], u10 = (r10 ? 2 : 0) + s11 + o13, h10 = new Array(u10), c10 = new Array(u10), p10 = 0, f11 = function(t18, e23) {
      c10[p10] = t18, h10[p10++] = e23;
    };
    if (r10) {
      var l11 = t17.bounds, d12 = e22.getCentre(l11), g9 = e22.getSize(l11) / 2, v12 = e22.getOpen(l11), y10 = e22.getClose(l11), _7 = d12 - g9 + i11 / 2, x11 = d12 + g9 - i11 / 2;
      t17.minVar.desiredPosition = _7, f11(e22.makeRect(v12, y10, _7, i11), t17.minVar), t17.maxVar.desiredPosition = x11, f11(e22.makeRect(v12, y10, x11, i11), t17.maxVar);
    }
    s11 && t17.leaves.forEach(function(t18) {
      return f11(t18.bounds, t18.variable);
    }), o13 && t17.groups.forEach(function(t18) {
      var n14 = t18.bounds;
      f11(e22.makeRect(e22.getOpen(n14), e22.getClose(n14), e22.getCentre(n14), e22.getSize(n14)), t18.minVar);
    });
    var m12 = U6(c10, h10, e22, n13);
    return o13 && (h10.forEach(function(t18) {
      t18.cOut = [], t18.cIn = [];
    }), m12.forEach(function(t18) {
      t18.left.cOut.push(t18), t18.right.cIn.push(t18);
    }), t17.groups.forEach(function(t18) {
      var n14 = (t18.padding - e22.getSize(t18.bounds)) / 2;
      t18.minVar.cIn.forEach(function(t19) {
        return t19.gap += n14;
      }), t18.minVar.cOut.forEach(function(e23) {
        e23.left = t18.maxVar, e23.gap += n14;
      });
    })), a10.concat(m12);
  }
  function U6(t17, e22, n13, r10) {
    var i11, o13 = t17.length, s11 = 2 * o13;
    console.assert(e22.length >= o13);
    var a10 = new Array(s11);
    for (i11 = 0; i11 < o13; ++i11) {
      var u10 = t17[i11], h10 = new R5(e22[i11], u10, n13.getCentre(u10));
      a10[i11] = new X5(true, h10, n13.getOpen(u10)), a10[i11 + o13] = new X5(false, h10, n13.getClose(u10));
    }
    a10.sort(z6);
    var c10 = new Array(), p10 = Y5();
    for (i11 = 0; i11 < s11; ++i11) {
      var f11 = a10[i11];
      h10 = f11.v;
      if (f11.isOpen)
        p10.insert(h10), n13.findNeighbours(h10, p10);
      else {
        p10.remove(h10);
        var l11 = function(t18, e23) {
          var i12 = (n13.getSize(t18.r) + n13.getSize(e23.r)) / 2 + r10;
          c10.push(new V6.Constraint(t18.v, e23.v, i12));
        }, d12 = function(t18, e23, n14) {
          for (var r11, i12 = h10[t18].iterator(); null !== (r11 = i12[t18]()); )
            n14(r11, h10), r11[e23].remove(h10);
        };
        d12("prev", "next", function(t18, e23) {
          return l11(t18, e23);
        }), d12("next", "prev", function(t18, e23) {
          return l11(e23, t18);
        });
      }
    }
    return console.assert(0 === p10.size), c10;
  }
  function W6(t17, e22) {
    return U6(t17, e22, q6, 1e-6);
  }
  function K5(t17, e22) {
    return U6(t17, e22, F7, 1e-6);
  }
  function Q5(t17) {
    return H5(t17, q6, 1e-6);
  }
  function Z5(t17) {
    return H5(t17, F7, 1e-6);
  }
  m8.generateXConstraints = W6, m8.generateYConstraints = K5, m8.generateXGroupConstraints = Q5, m8.generateYGroupConstraints = Z5, m8.removeOverlaps = function(t17) {
    var e22 = t17.map(function(t18) {
      return new V6.Variable(t18.cx());
    }), n13 = W6(t17, e22), r10 = new V6.Solver(e22, n13);
    r10.solve(), e22.forEach(function(e23, n14) {
      return t17[n14].setXCentre(e23.position());
    }), e22 = t17.map(function(t18) {
      return new V6.Variable(t18.cy());
    }), n13 = K5(t17, e22), (r10 = new V6.Solver(e22, n13)).solve(), e22.forEach(function(e23, n14) {
      return t17[n14].setYCentre(e23.position());
    });
  };
  var J5 = function(t17) {
    function e22(e23, n13) {
      var r10 = t17.call(this, 0, n13) || this;
      return r10.index = e23, r10;
    }
    return G5(e22, t17), e22;
  }(V6.Variable);
  m8.IndexedVariable = J5;
  var $7 = function() {
    function t17(t18, e22, n13, r10, i11) {
      var o13 = this;
      if (void 0 === n13 && (n13 = null), void 0 === r10 && (r10 = null), void 0 === i11 && (i11 = false), this.nodes = t18, this.groups = e22, this.rootGroup = n13, this.avoidOverlaps = i11, this.variables = t18.map(function(t19, e23) {
        return t19.variable = new J5(e23, 1);
      }), r10 && this.createConstraints(r10), i11 && n13 && void 0 !== n13.groups) {
        t18.forEach(function(t19) {
          if (t19.width && t19.height) {
            var e23 = t19.width / 2, n14 = t19.height / 2;
            t19.bounds = new B5(t19.x - e23, t19.x + e23, t19.y - n14, t19.y + n14);
          } else
            t19.bounds = new B5(t19.x, t19.x, t19.y, t19.y);
        }), j7(n13);
        var s11 = t18.length;
        e22.forEach(function(t19) {
          o13.variables[s11] = t19.minVar = new J5(s11++, void 0 !== t19.stiffness ? t19.stiffness : 0.01), o13.variables[s11] = t19.maxVar = new J5(s11++, void 0 !== t19.stiffness ? t19.stiffness : 0.01);
        });
      }
    }
    return t17.prototype.createSeparation = function(t18) {
      return new V6.Constraint(this.nodes[t18.left].variable, this.nodes[t18.right].variable, t18.gap, void 0 !== t18.equality && t18.equality);
    }, t17.prototype.makeFeasible = function(t18) {
      var e22 = this;
      if (this.avoidOverlaps) {
        var n13 = "x", r10 = "width";
        "x" === t18.axis && (n13 = "y", r10 = "height");
        var i11 = t18.offsets.map(function(t19) {
          return e22.nodes[t19.node];
        }).sort(function(t19, e23) {
          return t19[n13] - e23[n13];
        }), o13 = null;
        i11.forEach(function(t19) {
          if (o13) {
            var e23 = o13[n13] + o13[r10];
            e23 > t19[n13] && (t19[n13] = e23);
          }
          o13 = t19;
        });
      }
    }, t17.prototype.createAlignment = function(t18) {
      var e22 = this, n13 = this.nodes[t18.offsets[0].node].variable;
      this.makeFeasible(t18);
      var r10 = "x" === t18.axis ? this.xConstraints : this.yConstraints;
      t18.offsets.slice(1).forEach(function(t19) {
        var i11 = e22.nodes[t19.node].variable;
        r10.push(new V6.Constraint(n13, i11, t19.offset, true));
      });
    }, t17.prototype.createConstraints = function(t18) {
      var e22 = this, n13 = function(t19) {
        return void 0 === t19.type || "separation" === t19.type;
      };
      this.xConstraints = t18.filter(function(t19) {
        return "x" === t19.axis && n13(t19);
      }).map(function(t19) {
        return e22.createSeparation(t19);
      }), this.yConstraints = t18.filter(function(t19) {
        return "y" === t19.axis && n13(t19);
      }).map(function(t19) {
        return e22.createSeparation(t19);
      }), t18.filter(function(t19) {
        return "alignment" === t19.type;
      }).forEach(function(t19) {
        return e22.createAlignment(t19);
      });
    }, t17.prototype.setupVariablesAndBounds = function(t18, e22, n13, r10) {
      this.nodes.forEach(function(i11, o13) {
        i11.fixed ? (i11.variable.weight = i11.fixedWeight ? i11.fixedWeight : 1e3, n13[o13] = r10(i11)) : i11.variable.weight = 1;
        var s11 = (i11.width || 0) / 2, a10 = (i11.height || 0) / 2, u10 = t18[o13], h10 = e22[o13];
        i11.bounds = new B5(u10 - s11, u10 + s11, h10 - a10, h10 + a10);
      });
    }, t17.prototype.xProject = function(t18, e22, n13) {
      (this.rootGroup || this.avoidOverlaps || this.xConstraints) && this.project(t18, e22, t18, n13, function(t19) {
        return t19.px;
      }, this.xConstraints, Q5, function(t19) {
        return t19.bounds.setXCentre(n13[t19.variable.index] = t19.variable.position());
      }, function(t19) {
        var e23 = n13[t19.minVar.index] = t19.minVar.position(), r10 = n13[t19.maxVar.index] = t19.maxVar.position(), i11 = t19.padding / 2;
        t19.bounds.x = e23 - i11, t19.bounds.X = r10 + i11;
      });
    }, t17.prototype.yProject = function(t18, e22, n13) {
      (this.rootGroup || this.yConstraints) && this.project(t18, e22, e22, n13, function(t19) {
        return t19.py;
      }, this.yConstraints, Z5, function(t19) {
        return t19.bounds.setYCentre(n13[t19.variable.index] = t19.variable.position());
      }, function(t19) {
        var e23 = n13[t19.minVar.index] = t19.minVar.position(), r10 = n13[t19.maxVar.index] = t19.maxVar.position(), i11 = t19.padding / 2;
        t19.bounds.y = e23 - i11, t19.bounds.Y = r10 + i11;
      });
    }, t17.prototype.projectFunctions = function() {
      var t18 = this;
      return [function(e22, n13, r10) {
        return t18.xProject(e22, n13, r10);
      }, function(e22, n13, r10) {
        return t18.yProject(e22, n13, r10);
      }];
    }, t17.prototype.project = function(t18, e22, n13, r10, i11, o13, s11, a10, u10) {
      this.setupVariablesAndBounds(t18, e22, r10, i11), this.rootGroup && this.avoidOverlaps && (j7(this.rootGroup), o13 = o13.concat(s11(this.rootGroup))), this.solve(this.variables, o13, n13, r10), this.nodes.forEach(a10), this.rootGroup && this.avoidOverlaps && (this.groups.forEach(u10), j7(this.rootGroup));
    }, t17.prototype.solve = function(t18, e22, n13, r10) {
      var i11 = new V6.Solver(t18, e22);
      i11.setStartingPositions(n13), i11.setDesiredPositions(r10), i11.solve();
    }, t17;
  }();
  m8.Projection = $7;
  var tt5 = {};
  var et5 = {};
  Object.defineProperty(et5, "__esModule", { value: true });
  var nt5 = function() {
    function t17(t18) {
      this.elem = t18, this.subheaps = [];
    }
    return t17.prototype.toString = function(t18) {
      for (var e22 = "", n13 = false, r10 = 0; r10 < this.subheaps.length; ++r10) {
        var i11 = this.subheaps[r10];
        i11.elem ? (n13 && (e22 += ","), e22 += i11.toString(t18), n13 = true) : n13 = false;
      }
      return "" !== e22 && (e22 = "(" + e22 + ")"), (this.elem ? t18(this.elem) : "") + e22;
    }, t17.prototype.forEach = function(t18) {
      this.empty() || (t18(this.elem, this), this.subheaps.forEach(function(e22) {
        return e22.forEach(t18);
      }));
    }, t17.prototype.count = function() {
      return this.empty() ? 0 : 1 + this.subheaps.reduce(function(t18, e22) {
        return t18 + e22.count();
      }, 0);
    }, t17.prototype.min = function() {
      return this.elem;
    }, t17.prototype.empty = function() {
      return null == this.elem;
    }, t17.prototype.contains = function(t18) {
      if (this === t18)
        return true;
      for (var e22 = 0; e22 < this.subheaps.length; e22++)
        if (this.subheaps[e22].contains(t18))
          return true;
      return false;
    }, t17.prototype.isHeap = function(t18) {
      var e22 = this;
      return this.subheaps.every(function(n13) {
        return t18(e22.elem, n13.elem) && n13.isHeap(t18);
      });
    }, t17.prototype.insert = function(e22, n13) {
      return this.merge(new t17(e22), n13);
    }, t17.prototype.merge = function(t18, e22) {
      return this.empty() ? t18 : t18.empty() ? this : e22(this.elem, t18.elem) ? (this.subheaps.push(t18), this) : (t18.subheaps.push(this), t18);
    }, t17.prototype.removeMin = function(t18) {
      return this.empty() ? null : this.mergePairs(t18);
    }, t17.prototype.mergePairs = function(e22) {
      if (0 == this.subheaps.length)
        return new t17(null);
      if (1 == this.subheaps.length)
        return this.subheaps[0];
      var n13 = this.subheaps.pop().merge(this.subheaps.pop(), e22), r10 = this.mergePairs(e22);
      return n13.merge(r10, e22);
    }, t17.prototype.decreaseKey = function(e22, n13, r10, i11) {
      var o13 = e22.removeMin(i11);
      e22.elem = o13.elem, e22.subheaps = o13.subheaps, null !== r10 && null !== o13.elem && r10(e22.elem, e22);
      var s11 = new t17(n13);
      return null !== r10 && r10(n13, s11), this.merge(s11, i11);
    }, t17;
  }();
  et5.PairingHeap = nt5;
  var rt5 = function() {
    function t17(t18) {
      this.lessThan = t18;
    }
    return t17.prototype.top = function() {
      return this.empty() ? null : this.root.elem;
    }, t17.prototype.push = function() {
      for (var t18, e22 = [], n13 = 0; n13 < arguments.length; n13++)
        e22[n13] = arguments[n13];
      for (var r10, i11 = 0; r10 = e22[i11]; ++i11)
        t18 = new nt5(r10), this.root = this.empty() ? t18 : this.root.merge(t18, this.lessThan);
      return t18;
    }, t17.prototype.empty = function() {
      return !this.root || !this.root.elem;
    }, t17.prototype.isHeap = function() {
      return this.root.isHeap(this.lessThan);
    }, t17.prototype.forEach = function(t18) {
      this.root.forEach(t18);
    }, t17.prototype.pop = function() {
      if (this.empty())
        return null;
      var t18 = this.root.min();
      return this.root = this.root.removeMin(this.lessThan), t18;
    }, t17.prototype.reduceKey = function(t18, e22, n13) {
      void 0 === n13 && (n13 = null), this.root = this.root.decreaseKey(t18, e22, n13, this.lessThan);
    }, t17.prototype.toString = function(t18) {
      return this.root.toString(t18);
    }, t17.prototype.count = function() {
      return this.root.count();
    }, t17;
  }();
  et5.PriorityQueue = rt5, Object.defineProperty(tt5, "__esModule", { value: true });
  var it5 = et5;
  var ot5 = function(t17, e22) {
    this.id = t17, this.distance = e22;
  };
  var st5 = function(t17) {
    this.id = t17, this.neighbours = [];
  };
  var at5 = function(t17, e22, n13) {
    this.node = t17, this.prev = e22, this.d = n13;
  };
  var ut5 = function() {
    function t17(t18, e22, n13, r10, i11) {
      this.n = t18, this.es = e22, this.neighbours = new Array(this.n);
      for (var o13 = this.n; o13--; )
        this.neighbours[o13] = new st5(o13);
      for (o13 = this.es.length; o13--; ) {
        var s11 = this.es[o13], a10 = n13(s11), u10 = r10(s11), h10 = i11(s11);
        this.neighbours[a10].neighbours.push(new ot5(u10, h10)), this.neighbours[u10].neighbours.push(new ot5(a10, h10));
      }
    }
    return t17.prototype.DistanceMatrix = function() {
      for (var t18 = new Array(this.n), e22 = 0; e22 < this.n; ++e22)
        t18[e22] = this.dijkstraNeighbours(e22);
      return t18;
    }, t17.prototype.DistancesFromNode = function(t18) {
      return this.dijkstraNeighbours(t18);
    }, t17.prototype.PathFromNodeToNode = function(t18, e22) {
      return this.dijkstraNeighbours(t18, e22);
    }, t17.prototype.PathFromNodeToNodeWithPrevCost = function(t18, e22, n13) {
      var r10 = new it5.PriorityQueue(function(t19, e23) {
        return t19.d <= e23.d;
      }), i11 = this.neighbours[t18], o13 = new at5(i11, null, 0), s11 = {};
      for (r10.push(o13); !r10.empty() && (i11 = (o13 = r10.pop()).node).id !== e22; )
        for (var a10 = i11.neighbours.length; a10--; ) {
          var u10 = i11.neighbours[a10], h10 = this.neighbours[u10.id];
          if (!o13.prev || h10.id !== o13.prev.node.id) {
            var c10 = h10.id + "," + i11.id;
            if (!(c10 in s11 && s11[c10] <= o13.d)) {
              var p10 = o13.prev ? n13(o13.prev.node.id, i11.id, h10.id) : 0, f11 = o13.d + u10.distance + p10;
              s11[c10] = f11, r10.push(new at5(h10, o13, f11));
            }
          }
        }
      for (var l11 = []; o13.prev; )
        o13 = o13.prev, l11.push(o13.node.id);
      return l11;
    }, t17.prototype.dijkstraNeighbours = function(t18, e22) {
      void 0 === e22 && (e22 = -1);
      for (var n13 = new it5.PriorityQueue(function(t19, e23) {
        return t19.d <= e23.d;
      }), r10 = this.neighbours.length, i11 = new Array(r10); r10--; ) {
        var o13 = this.neighbours[r10];
        o13.d = r10 === t18 ? 0 : Number.POSITIVE_INFINITY, o13.q = n13.push(o13);
      }
      for (; !n13.empty(); ) {
        var s11 = n13.pop();
        if (i11[s11.id] = s11.d, s11.id === e22) {
          for (var a10 = [], u10 = s11; void 0 !== u10.prev; )
            a10.push(u10.prev.id), u10 = u10.prev;
          return a10;
        }
        for (r10 = s11.neighbours.length; r10--; ) {
          var h10 = s11.neighbours[r10], c10 = (u10 = this.neighbours[h10.id], s11.d + h10.distance);
          s11.d !== Number.MAX_VALUE && u10.d > c10 && (u10.d = c10, u10.prev = s11, n13.reduceKey(u10.q, u10, function(t19, e23) {
            return t19.q = e23;
          }));
        }
      }
      return i11;
    }, t17;
  }();
  tt5.Calculator = ut5;
  var ht5 = {};
  var ct5 = t11 && t11.__extends || function() {
    var t17 = function(e22, n13) {
      return t17 = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function(t18, e23) {
        t18.__proto__ = e23;
      } || function(t18, e23) {
        for (var n14 in e23)
          e23.hasOwnProperty(n14) && (t18[n14] = e23[n14]);
      }, t17(e22, n13);
    };
    return function(e22, n13) {
      function r10() {
        this.constructor = e22;
      }
      t17(e22, n13), e22.prototype = null === n13 ? Object.create(n13) : (r10.prototype = n13.prototype, new r10());
    };
  }();
  Object.defineProperty(ht5, "__esModule", { value: true });
  var pt5 = m8;
  var ft5 = function() {
  };
  ht5.Point = ft5;
  var lt5 = function(t17, e22, n13, r10) {
    this.x1 = t17, this.y1 = e22, this.x2 = n13, this.y2 = r10;
  };
  ht5.LineSegment = lt5;
  var dt5 = function(t17) {
    function e22() {
      return null !== t17 && t17.apply(this, arguments) || this;
    }
    return ct5(e22, t17), e22;
  }(ft5);
  function gt5(t17, e22, n13) {
    return (e22.x - t17.x) * (n13.y - t17.y) - (n13.x - t17.x) * (e22.y - t17.y);
  }
  function vt5(t17, e22, n13) {
    return gt5(t17, e22, n13) > 0;
  }
  function yt5(t17, e22, n13) {
    return gt5(t17, e22, n13) < 0;
  }
  function _t5(t17, e22) {
    var n13, r10, i11, o13, s11 = e22.length - 1;
    if (yt5(t17, e22[1], e22[0]) && !vt5(t17, e22[s11 - 1], e22[0]))
      return 0;
    for (n13 = 0, r10 = s11; ; ) {
      if (r10 - n13 == 1)
        return vt5(t17, e22[n13], e22[r10]) ? n13 : r10;
      if ((o13 = yt5(t17, e22[(i11 = Math.floor((n13 + r10) / 2)) + 1], e22[i11])) && !vt5(t17, e22[i11 - 1], e22[i11]))
        return i11;
      vt5(t17, e22[n13 + 1], e22[n13]) ? o13 || vt5(t17, e22[n13], e22[i11]) ? r10 = i11 : n13 = i11 : o13 && yt5(t17, e22[n13], e22[i11]) ? r10 = i11 : n13 = i11;
    }
  }
  function xt5(t17, e22) {
    var n13, r10, i11, o13, s11 = e22.length - 1;
    if (vt5(t17, e22[s11 - 1], e22[0]) && !yt5(t17, e22[1], e22[0]))
      return 0;
    for (n13 = 0, r10 = s11; ; ) {
      if (r10 - n13 == 1)
        return yt5(t17, e22[n13], e22[r10]) ? n13 : r10;
      if (o13 = yt5(t17, e22[(i11 = Math.floor((n13 + r10) / 2)) + 1], e22[i11]), vt5(t17, e22[i11 - 1], e22[i11]) && !o13)
        return i11;
      yt5(t17, e22[n13 + 1], e22[n13]) ? o13 ? yt5(t17, e22[n13], e22[i11]) ? r10 = i11 : n13 = i11 : r10 = i11 : o13 ? n13 = i11 : vt5(t17, e22[n13], e22[i11]) ? r10 = i11 : n13 = i11;
    }
  }
  function mt5(t17, e22, n13, r10, i11, o13) {
    var s11, a10;
    a10 = r10(t17[s11 = n13(e22[0], t17)], e22);
    for (var u10 = false; !u10; ) {
      for (u10 = true; s11 === t17.length - 1 && (s11 = 0), !i11(e22[a10], t17[s11], t17[s11 + 1]); )
        ++s11;
      for (; 0 === a10 && (a10 = e22.length - 1), !o13(t17[s11], e22[a10], e22[a10 - 1]); )
        --a10, u10 = false;
    }
    return { t1: s11, t2: a10 };
  }
  function bt5(t17, e22) {
    return mt5(t17, e22, _t5, xt5, vt5, yt5);
  }
  ht5.PolyPoint = dt5, ht5.isLeft = gt5, ht5.ConvexHull = function(t17) {
    var e22, n13 = t17.slice(0).sort(function(t18, e23) {
      return t18.x !== e23.x ? e23.x - t18.x : e23.y - t18.y;
    }), r10 = t17.length, i11 = n13[0].x;
    for (e22 = 1; e22 < r10 && n13[e22].x === i11; ++e22)
      ;
    var o13 = e22 - 1, s11 = [];
    if (s11.push(n13[0]), o13 === r10 - 1)
      n13[o13].y !== n13[0].y && s11.push(n13[o13]);
    else {
      var a10, u10 = r10 - 1, h10 = n13[r10 - 1].x;
      for (e22 = r10 - 2; e22 >= 0 && n13[e22].x === h10; e22--)
        ;
      for (a10 = e22 + 1, e22 = o13; ++e22 <= a10; )
        if (!(gt5(n13[0], n13[a10], n13[e22]) >= 0 && e22 < a10)) {
          for (; s11.length > 1 && !(gt5(s11[s11.length - 2], s11[s11.length - 1], n13[e22]) > 0); )
            s11.length -= 1;
          0 != e22 && s11.push(n13[e22]);
        }
      u10 != a10 && s11.push(n13[u10]);
      var c10 = s11.length;
      for (e22 = a10; --e22 >= o13; )
        if (!(gt5(n13[u10], n13[o13], n13[e22]) >= 0 && e22 > o13)) {
          for (; s11.length > c10 && !(gt5(s11[s11.length - 2], s11[s11.length - 1], n13[e22]) > 0); )
            s11.length -= 1;
          0 != e22 && s11.push(n13[e22]);
        }
    }
    return s11;
  }, ht5.clockwiseRadialSweep = function(t17, e22, n13) {
    e22.slice(0).sort(function(e23, n14) {
      return Math.atan2(e23.y - t17.y, e23.x - t17.x) - Math.atan2(n14.y - t17.y, n14.x - t17.x);
    }).forEach(n13);
  }, ht5.tangent_PolyPolyC = mt5, ht5.LRtangent_PolyPolyC = function(t17, e22) {
    var n13 = bt5(e22, t17);
    return { t1: n13.t2, t2: n13.t1 };
  }, ht5.RLtangent_PolyPolyC = bt5, ht5.LLtangent_PolyPolyC = function(t17, e22) {
    return mt5(t17, e22, xt5, xt5, yt5, yt5);
  }, ht5.RRtangent_PolyPolyC = function(t17, e22) {
    return mt5(t17, e22, _t5, _t5, vt5, vt5);
  };
  var kt5 = function(t17, e22) {
    this.t1 = t17, this.t2 = e22;
  };
  ht5.BiTangent = kt5;
  var wt5 = function() {
  };
  ht5.BiTangents = wt5;
  var Et5 = function(t17) {
    function e22() {
      return null !== t17 && t17.apply(this, arguments) || this;
    }
    return ct5(e22, t17), e22;
  }(ft5);
  ht5.TVGPoint = Et5;
  var Pt5 = function(t17, e22, n13, r10) {
    this.id = t17, this.polyid = e22, this.polyvertid = n13, this.p = r10, r10.vv = this;
  };
  ht5.VisibilityVertex = Pt5;
  var Lt5 = function() {
    function t17(t18, e22) {
      this.source = t18, this.target = e22;
    }
    return t17.prototype.length = function() {
      var t18 = this.source.p.x - this.target.p.x, e22 = this.source.p.y - this.target.p.y;
      return Math.sqrt(t18 * t18 + e22 * e22);
    }, t17;
  }();
  ht5.VisibilityEdge = Lt5;
  var Mt5 = function() {
    function t17(t18, e22) {
      if (this.P = t18, this.V = [], this.E = [], e22)
        this.V = e22.V.slice(0), this.E = e22.E.slice(0);
      else {
        for (var n13 = t18.length, r10 = 0; r10 < n13; r10++) {
          for (var i11 = t18[r10], o13 = 0; o13 < i11.length; ++o13) {
            var s11 = i11[o13], a10 = new Pt5(this.V.length, r10, o13, s11);
            this.V.push(a10), o13 > 0 && this.E.push(new Lt5(i11[o13 - 1].vv, a10));
          }
          i11.length > 1 && this.E.push(new Lt5(i11[0].vv, i11[i11.length - 1].vv));
        }
        for (r10 = 0; r10 < n13 - 1; r10++) {
          var u10 = t18[r10];
          for (o13 = r10 + 1; o13 < n13; o13++) {
            var h10 = t18[o13], c10 = St5(u10, h10);
            for (var p10 in c10) {
              var f11 = c10[p10], l11 = u10[f11.t1], d12 = h10[f11.t2];
              this.addEdgeIfVisible(l11, d12, r10, o13);
            }
          }
        }
      }
    }
    return t17.prototype.addEdgeIfVisible = function(t18, e22, n13, r10) {
      this.intersectsPolys(new lt5(t18.x, t18.y, e22.x, e22.y), n13, r10) || this.E.push(new Lt5(t18.vv, e22.vv));
    }, t17.prototype.addPoint = function(t18, e22) {
      var n13, r10, i11, o13 = this.P.length;
      this.V.push(new Pt5(this.V.length, o13, 0, t18));
      for (var s11 = 0; s11 < o13; ++s11)
        if (s11 !== e22) {
          var a10 = this.P[s11], u10 = (n13 = t18, i11 = void 0, (i11 = (r10 = a10).slice(0)).push(r10[0]), { rtan: _t5(n13, i11), ltan: xt5(n13, i11) });
          this.addEdgeIfVisible(t18, a10[u10.ltan], e22, s11), this.addEdgeIfVisible(t18, a10[u10.rtan], e22, s11);
        }
      return t18.vv;
    }, t17.prototype.intersectsPolys = function(t18, e22, n13) {
      for (var r10 = 0, i11 = this.P.length; r10 < i11; ++r10)
        if (r10 != e22 && r10 != n13 && At5(t18, this.P[r10]).length > 0)
          return true;
      return false;
    }, t17;
  }();
  function At5(t17, e22) {
    for (var n13 = [], r10 = 1, i11 = e22.length; r10 < i11; ++r10) {
      var o13 = pt5.Rectangle.lineIntersection(t17.x1, t17.y1, t17.x2, t17.y2, e22[r10 - 1].x, e22[r10 - 1].y, e22[r10].x, e22[r10].y);
      o13 && n13.push(o13);
    }
    return n13;
  }
  function St5(t17, e22) {
    for (var n13 = t17.length - 1, r10 = e22.length - 1, i11 = new wt5(), o13 = 0; o13 < n13; ++o13)
      for (var s11 = 0; s11 < r10; ++s11) {
        var a10 = t17[0 == o13 ? n13 - 1 : o13 - 1], u10 = t17[o13], h10 = t17[o13 + 1], c10 = e22[0 == s11 ? r10 - 1 : s11 - 1], p10 = e22[s11], f11 = e22[s11 + 1], l11 = gt5(a10, u10, p10), d12 = gt5(u10, c10, p10), g9 = gt5(u10, p10, f11), v12 = gt5(c10, p10, u10), y10 = gt5(p10, a10, u10), _7 = gt5(p10, u10, h10);
        l11 >= 0 && d12 >= 0 && g9 < 0 && v12 >= 0 && y10 >= 0 && _7 < 0 ? i11.ll = new kt5(o13, s11) : l11 <= 0 && d12 <= 0 && g9 > 0 && v12 <= 0 && y10 <= 0 && _7 > 0 ? i11.rr = new kt5(o13, s11) : l11 <= 0 && d12 > 0 && g9 <= 0 && v12 >= 0 && y10 < 0 && _7 >= 0 ? i11.rl = new kt5(o13, s11) : l11 >= 0 && d12 < 0 && g9 >= 0 && v12 <= 0 && y10 > 0 && _7 <= 0 && (i11.lr = new kt5(o13, s11));
      }
    return i11;
  }
  function Ot5(t17, e22) {
    return !t17.every(function(t18) {
      return !function(t19, e23) {
        for (var n13 = 1, r10 = e23.length; n13 < r10; ++n13)
          if (yt5(e23[n13 - 1], e23[n13], t19))
            return false;
        return true;
      }(t18, e22);
    });
  }
  ht5.TangentVisibilityGraph = Mt5, ht5.tangents = St5, ht5.polysOverlap = function(t17, e22) {
    if (Ot5(t17, e22))
      return true;
    if (Ot5(e22, t17))
      return true;
    for (var n13 = 1, r10 = t17.length; n13 < r10; ++n13) {
      var i11 = t17[n13], o13 = t17[n13 - 1];
      if (At5(new lt5(o13.x, o13.y, i11.x, i11.y), e22).length > 0)
        return true;
    }
    return false;
  };
  var Ct5 = {};
  Object.defineProperty(Ct5, "__esModule", { value: true });
  var Nt5 = 10;
  var It5 = (1 + Math.sqrt(5)) / 2;
  var Tt5 = 1e-4;
  Ct5.applyPacking = function(t17, e22, n13, r10, i11, o13) {
    void 0 === i11 && (i11 = 1), void 0 === o13 && (o13 = true);
    var s11 = 0, a10 = 0, u10 = e22, h10 = n13, c10 = (i11 = void 0 !== i11 ? i11 : 1, r10 = void 0 !== r10 ? r10 : 0, 0), p10 = 0, f11 = 0, l11 = 0, d12 = [];
    function g9(t18, e23) {
      d12 = [], c10 = 0, p10 = 0, l11 = a10;
      for (var n14 = 0; n14 < t18.length; n14++) {
        v12(t18[n14], e23);
      }
      return Math.abs(c10 / p10 - i11);
    }
    function v12(t18, e23) {
      for (var n14 = void 0, r11 = 0; r11 < d12.length; r11++)
        if (d12[r11].space_left >= t18.height && d12[r11].x + d12[r11].width + t18.width + Nt5 - e23 <= Tt5) {
          n14 = d12[r11];
          break;
        }
      d12.push(t18), void 0 !== n14 ? (t18.x = n14.x + n14.width + Nt5, t18.y = n14.bottom, t18.space_left = t18.height, t18.bottom = t18.y, n14.space_left -= t18.height + Nt5, n14.bottom += t18.height + Nt5) : (t18.y = l11, l11 += t18.height + Nt5, t18.x = s11, t18.bottom = t18.y, t18.space_left = t18.height), t18.y + t18.height - p10 > -Tt5 && (p10 = t18.y + t18.height - a10), t18.x + t18.width - c10 > -Tt5 && (c10 = t18.x + t18.width - s11);
    }
    0 != t17.length && (function(t18) {
      t18.forEach(function(t19) {
        var e23, n14, i12, o14, s12;
        e23 = t19, n14 = Number.MAX_VALUE, i12 = Number.MAX_VALUE, o14 = 0, s12 = 0, e23.array.forEach(function(t20) {
          var e24 = void 0 !== t20.width ? t20.width : r10, a11 = void 0 !== t20.height ? t20.height : r10;
          e24 /= 2, a11 /= 2, o14 = Math.max(t20.x + e24, o14), n14 = Math.min(t20.x - e24, n14), s12 = Math.max(t20.y + a11, s12), i12 = Math.min(t20.y - a11, i12);
        }), e23.width = o14 - n14, e23.height = s12 - i12;
      });
    }(t17), function(t18, e23) {
      var n14 = Number.POSITIVE_INFINITY, r11 = 0;
      t18.sort(function(t19, e24) {
        return e24.height - t19.height;
      }), f11 = t18.reduce(function(t19, e24) {
        return t19.width < e24.width ? t19.width : e24.width;
      });
      var i12 = l12 = f11, o14 = d13 = function(t19) {
        var e24 = 0;
        return t19.forEach(function(t20) {
          return e24 += t20.width + Nt5;
        }), e24;
      }(t18), s12 = 0, a11 = Number.MAX_VALUE, u11 = Number.MAX_VALUE, h11 = -1, c11 = Number.MAX_VALUE, p11 = Number.MAX_VALUE;
      for (; c11 > f11 || p11 > Tt5; ) {
        if (1 != h11) {
          var l12 = o14 - (o14 - i12) / It5;
          a11 = g9(t18, l12);
        }
        if (0 != h11) {
          var d13 = i12 + (o14 - i12) / It5;
          u11 = g9(t18, d13);
        }
        if (c11 = Math.abs(l12 - d13), p11 = Math.abs(a11 - u11), a11 < n14 && (n14 = a11, r11 = l12), u11 < n14 && (n14 = u11, r11 = d13), a11 > u11 ? (i12 = l12, l12 = d13, a11 = u11, h11 = 1) : (o14 = d13, d13 = l12, u11 = a11, h11 = 0), s12++ > 100)
          break;
      }
      g9(t18, r11);
    }(t17), o13 && function(t18) {
      t18.forEach(function(t19) {
        var e23 = { x: 0, y: 0 };
        t19.array.forEach(function(t20) {
          e23.x += t20.x, e23.y += t20.y;
        }), e23.x /= t19.array.length, e23.y /= t19.array.length;
        var n14 = { x: e23.x - t19.width / 2, y: e23.y - t19.height / 2 }, r11 = { x: t19.x - n14.x + u10 / 2 - c10 / 2, y: t19.y - n14.y + h10 / 2 - p10 / 2 };
        t19.array.forEach(function(t20) {
          t20.x += r11.x, t20.y += r11.y;
        });
      });
    }(t17));
  }, Ct5.separateGraphs = function(t17, e22) {
    for (var n13 = {}, r10 = {}, i11 = [], o13 = 0, s11 = 0; s11 < e22.length; s11++) {
      var a10 = e22[s11], u10 = a10.source, h10 = a10.target;
      r10[u10.index] ? r10[u10.index].push(h10) : r10[u10.index] = [h10], r10[h10.index] ? r10[h10.index].push(u10) : r10[h10.index] = [u10];
    }
    for (s11 = 0; s11 < t17.length; s11++) {
      var c10 = t17[s11];
      n13[c10.index] || p10(c10, true);
    }
    function p10(t18, e23) {
      if (void 0 === n13[t18.index]) {
        e23 && (o13++, i11.push({ array: [] })), n13[t18.index] = o13, i11[o13 - 1].array.push(t18);
        var s12 = r10[t18.index];
        if (s12)
          for (var a11 = 0; a11 < s12.length; a11++)
            p10(s12[a11], false);
      }
    }
    return i11;
  }, function(t17) {
    Object.defineProperty(t17, "__esModule", { value: true });
    var e22, n13 = i7, r10 = p7, o13 = v7, s11 = m8, a10 = tt5, u10 = ht5, h10 = Ct5;
    function c10(t18) {
      return void 0 !== t18.leaves || void 0 !== t18.groups;
    }
    !function(t18) {
      t18[t18.start = 0] = "start", t18[t18.tick = 1] = "tick", t18[t18.end = 2] = "end";
    }(e22 = t17.EventType || (t17.EventType = {}));
    var f11 = function() {
      function t18() {
        var e23 = this;
        this._canvasSize = [1, 1], this._linkDistance = 20, this._defaultNodeSize = 10, this._linkLengthCalculator = null, this._linkType = null, this._avoidOverlaps = false, this._handleDisconnected = true, this._running = false, this._nodes = [], this._groups = [], this._rootGroup = null, this._links = [], this._constraints = [], this._distanceMatrix = null, this._descent = null, this._directedLinkConstraints = null, this._threshold = 0.01, this._visibilityGraph = null, this._groupCompactness = 1e-6, this.event = null, this.linkAccessor = { getSourceIndex: t18.getSourceIndex, getTargetIndex: t18.getTargetIndex, setLength: t18.setLinkLength, getType: function(t19) {
          return "function" == typeof e23._linkType ? e23._linkType(t19) : 0;
        } };
      }
      return t18.prototype.on = function(t19, n14) {
        return this.event || (this.event = {}), "string" == typeof t19 ? this.event[e22[t19]] = n14 : this.event[t19] = n14, this;
      }, t18.prototype.trigger = function(t19) {
        this.event && void 0 !== this.event[t19.type] && this.event[t19.type](t19);
      }, t18.prototype.kick = function() {
        for (; !this.tick(); )
          ;
      }, t18.prototype.tick = function() {
        if (this._alpha < this._threshold)
          return this._running = false, this.trigger({ type: e22.end, alpha: this._alpha = 0, stress: this._lastStress }), true;
        var t19, n14, r11 = this._nodes.length;
        for (this._links.length, this._descent.locks.clear(), n14 = 0; n14 < r11; ++n14)
          if ((t19 = this._nodes[n14]).fixed) {
            void 0 !== t19.px && void 0 !== t19.py || (t19.px = t19.x, t19.py = t19.y);
            var i11 = [t19.px, t19.py];
            this._descent.locks.add(n14, i11);
          }
        var o14 = this._descent.rungeKutta();
        return 0 === o14 ? this._alpha = 0 : void 0 !== this._lastStress && (this._alpha = o14), this._lastStress = o14, this.updateNodePositions(), this.trigger({ type: e22.tick, alpha: this._alpha, stress: this._lastStress }), false;
      }, t18.prototype.updateNodePositions = function() {
        for (var t19, e23 = this._descent.x[0], n14 = this._descent.x[1], r11 = this._nodes.length; r11--; )
          (t19 = this._nodes[r11]).x = e23[r11], t19.y = n14[r11];
      }, t18.prototype.nodes = function(t19) {
        if (!t19) {
          if (0 === this._nodes.length && this._links.length > 0) {
            var e23 = 0;
            this._links.forEach(function(t20) {
              e23 = Math.max(e23, t20.source, t20.target);
            }), this._nodes = new Array(++e23);
            for (var n14 = 0; n14 < e23; ++n14)
              this._nodes[n14] = {};
          }
          return this._nodes;
        }
        return this._nodes = t19, this;
      }, t18.prototype.groups = function(t19) {
        var e23 = this;
        return t19 ? (this._groups = t19, this._rootGroup = {}, this._groups.forEach(function(t20) {
          void 0 === t20.padding && (t20.padding = 1), void 0 !== t20.leaves && t20.leaves.forEach(function(n14, r11) {
            "number" == typeof n14 && ((t20.leaves[r11] = e23._nodes[n14]).parent = t20);
          }), void 0 !== t20.groups && t20.groups.forEach(function(n14, r11) {
            "number" == typeof n14 && ((t20.groups[r11] = e23._groups[n14]).parent = t20);
          });
        }), this._rootGroup.leaves = this._nodes.filter(function(t20) {
          return void 0 === t20.parent;
        }), this._rootGroup.groups = this._groups.filter(function(t20) {
          return void 0 === t20.parent;
        }), this) : this._groups;
      }, t18.prototype.powerGraphGroups = function(t19) {
        var e23 = n13.getGroups(this._nodes, this._links, this.linkAccessor, this._rootGroup);
        return this.groups(e23.groups), t19(e23), this;
      }, t18.prototype.avoidOverlaps = function(t19) {
        return arguments.length ? (this._avoidOverlaps = t19, this) : this._avoidOverlaps;
      }, t18.prototype.handleDisconnected = function(t19) {
        return arguments.length ? (this._handleDisconnected = t19, this) : this._handleDisconnected;
      }, t18.prototype.flowLayout = function(t19, e23) {
        return arguments.length || (t19 = "y"), this._directedLinkConstraints = { axis: t19, getMinSeparation: "number" == typeof e23 ? function() {
          return e23;
        } : e23 }, this;
      }, t18.prototype.links = function(t19) {
        return arguments.length ? (this._links = t19, this) : this._links;
      }, t18.prototype.constraints = function(t19) {
        return arguments.length ? (this._constraints = t19, this) : this._constraints;
      }, t18.prototype.distanceMatrix = function(t19) {
        return arguments.length ? (this._distanceMatrix = t19, this) : this._distanceMatrix;
      }, t18.prototype.size = function(t19) {
        return t19 ? (this._canvasSize = t19, this) : this._canvasSize;
      }, t18.prototype.defaultNodeSize = function(t19) {
        return t19 ? (this._defaultNodeSize = t19, this) : this._defaultNodeSize;
      }, t18.prototype.groupCompactness = function(t19) {
        return t19 ? (this._groupCompactness = t19, this) : this._groupCompactness;
      }, t18.prototype.linkDistance = function(t19) {
        return t19 ? (this._linkDistance = "function" == typeof t19 ? t19 : +t19, this._linkLengthCalculator = null, this) : this._linkDistance;
      }, t18.prototype.linkType = function(t19) {
        return this._linkType = t19, this;
      }, t18.prototype.convergenceThreshold = function(t19) {
        return t19 ? (this._threshold = "function" == typeof t19 ? t19 : +t19, this) : this._threshold;
      }, t18.prototype.alpha = function(t19) {
        return arguments.length ? (t19 = +t19, this._alpha ? this._alpha = t19 > 0 ? t19 : 0 : t19 > 0 && (this._running || (this._running = true, this.trigger({ type: e22.start, alpha: this._alpha = t19 }), this.kick())), this) : this._alpha;
      }, t18.prototype.getLinkLength = function(t19) {
        return "function" == typeof this._linkDistance ? +this._linkDistance(t19) : this._linkDistance;
      }, t18.setLinkLength = function(t19, e23) {
        t19.length = e23;
      }, t18.prototype.getLinkType = function(t19) {
        return "function" == typeof this._linkType ? this._linkType(t19) : 0;
      }, t18.prototype.symmetricDiffLinkLengths = function(t19, e23) {
        var n14 = this;
        return void 0 === e23 && (e23 = 1), this.linkDistance(function(e24) {
          return t19 * e24.length;
        }), this._linkLengthCalculator = function() {
          return r10.symmetricDiffLinkLengths(n14._links, n14.linkAccessor, e23);
        }, this;
      }, t18.prototype.jaccardLinkLengths = function(t19, e23) {
        var n14 = this;
        return void 0 === e23 && (e23 = 1), this.linkDistance(function(e24) {
          return t19 * e24.length;
        }), this._linkLengthCalculator = function() {
          return r10.jaccardLinkLengths(n14._links, n14.linkAccessor, e23);
        }, this;
      }, t18.prototype.start = function(e23, n14, i11, u11, h11, c11) {
        var p10 = this;
        void 0 === e23 && (e23 = 0), void 0 === n14 && (n14 = 0), void 0 === i11 && (i11 = 0), void 0 === u11 && (u11 = 0), void 0 === h11 && (h11 = true), void 0 === c11 && (c11 = true);
        var f12 = this.nodes().length, l11 = f12 + 2 * this._groups.length;
        this._links.length;
        var d12, g9 = this._canvasSize[0], v12 = this._canvasSize[1], y10 = new Array(l11), _7 = new Array(l11), x11 = null, m12 = this._avoidOverlaps;
        this._nodes.forEach(function(t19, e24) {
          t19.index = e24, void 0 === t19.x && (t19.x = g9 / 2, t19.y = v12 / 2), y10[e24] = t19.x, _7[e24] = t19.y;
        }), this._linkLengthCalculator && this._linkLengthCalculator(), this._distanceMatrix ? d12 = this._distanceMatrix : (d12 = new a10.Calculator(l11, this._links, t18.getSourceIndex, t18.getTargetIndex, function(t19) {
          return p10.getLinkLength(t19);
        }).DistanceMatrix(), x11 = o13.Descent.createSquareMatrix(l11, function() {
          return 2;
        }), this._links.forEach(function(t19) {
          "number" == typeof t19.source && (t19.source = p10._nodes[t19.source]), "number" == typeof t19.target && (t19.target = p10._nodes[t19.target]);
        }), this._links.forEach(function(e24) {
          var n15 = t18.getSourceIndex(e24), r11 = t18.getTargetIndex(e24);
          x11[n15][r11] = x11[r11][n15] = e24.weight || 1;
        }));
        var b11 = o13.Descent.createSquareMatrix(l11, function(t19, e24) {
          return d12[t19][e24];
        });
        if (this._rootGroup && void 0 !== this._rootGroup.groups) {
          var k10 = f12;
          this._groups.forEach(function(t19) {
            !function(t20, e24, n15, r11) {
              x11[t20][e24] = x11[e24][t20] = n15, b11[t20][e24] = b11[e24][t20] = r11;
            }(k10, k10 + 1, p10._groupCompactness, 0.1), y10[k10] = 0, _7[k10++] = 0, y10[k10] = 0, _7[k10++] = 0;
          });
        } else
          this._rootGroup = { leaves: this._nodes, groups: [] };
        var w10 = this._constraints || [];
        this._directedLinkConstraints && (this.linkAccessor.getMinSeparation = this._directedLinkConstraints.getMinSeparation, w10 = w10.concat(r10.generateDirectedEdgeConstraints(f12, this._links, this._directedLinkConstraints.axis, this.linkAccessor))), this.avoidOverlaps(false), this._descent = new o13.Descent([y10, _7], b11), this._descent.locks.clear();
        for (k10 = 0; k10 < f12; ++k10) {
          var E10 = this._nodes[k10];
          if (E10.fixed) {
            E10.px = E10.x, E10.py = E10.y;
            var P10 = [E10.x, E10.y];
            this._descent.locks.add(k10, P10);
          }
        }
        if (this._descent.threshold = this._threshold, this.initialLayout(e23, y10, _7), w10.length > 0 && (this._descent.project = new s11.Projection(this._nodes, this._groups, this._rootGroup, w10).projectFunctions()), this._descent.run(n14), this.separateOverlappingComponents(g9, v12, c11), this.avoidOverlaps(m12), m12 && (this._nodes.forEach(function(t19, e24) {
          t19.x = y10[e24], t19.y = _7[e24];
        }), this._descent.project = new s11.Projection(this._nodes, this._groups, this._rootGroup, w10, true).projectFunctions(), this._nodes.forEach(function(t19, e24) {
          y10[e24] = t19.x, _7[e24] = t19.y;
        })), this._descent.G = x11, this._descent.run(i11), u11) {
          this._descent.snapStrength = 1e3, this._descent.snapGridSize = this._nodes[0].width, this._descent.numGridSnapNodes = f12, this._descent.scaleSnapByMaxH = f12 != l11;
          var L10 = o13.Descent.createSquareMatrix(l11, function(t19, e24) {
            return t19 >= f12 || e24 >= f12 ? x11[t19][e24] : 0;
          });
          this._descent.G = L10, this._descent.run(u11);
        }
        return this.updateNodePositions(), this.separateOverlappingComponents(g9, v12, c11), h11 ? this.resume() : this;
      }, t18.prototype.initialLayout = function(e23, n14, r11) {
        if (this._groups.length > 0 && e23 > 0) {
          var i11 = this._nodes.length, o14 = this._links.map(function(t19) {
            return { source: t19.source.index, target: t19.target.index };
          }), s12 = this._nodes.map(function(t19) {
            return { index: t19.index };
          });
          this._groups.forEach(function(t19, e24) {
            s12.push({ index: t19.index = i11 + e24 });
          }), this._groups.forEach(function(t19, e24) {
            void 0 !== t19.leaves && t19.leaves.forEach(function(e25) {
              return o14.push({ source: t19.index, target: e25.index });
            }), void 0 !== t19.groups && t19.groups.forEach(function(e25) {
              return o14.push({ source: t19.index, target: e25.index });
            });
          }), new t18().size(this.size()).nodes(s12).links(o14).avoidOverlaps(false).linkDistance(this.linkDistance()).symmetricDiffLinkLengths(5).convergenceThreshold(1e-4).start(e23, 0, 0, 0, false), this._nodes.forEach(function(t19) {
            n14[t19.index] = s12[t19.index].x, r11[t19.index] = s12[t19.index].y;
          });
        } else
          this._descent.run(e23);
      }, t18.prototype.separateOverlappingComponents = function(t19, e23, n14) {
        var r11 = this;
        if (void 0 === n14 && (n14 = true), !this._distanceMatrix && this._handleDisconnected) {
          var i11 = this._descent.x[0], o14 = this._descent.x[1];
          this._nodes.forEach(function(t20, e24) {
            t20.x = i11[e24], t20.y = o14[e24];
          });
          var s12 = h10.separateGraphs(this._nodes, this._links);
          h10.applyPacking(s12, t19, e23, this._defaultNodeSize, 1, n14), this._nodes.forEach(function(t20, e24) {
            r11._descent.x[0][e24] = t20.x, r11._descent.x[1][e24] = t20.y, t20.bounds && (t20.bounds.setXCentre(t20.x), t20.bounds.setYCentre(t20.y));
          });
        }
      }, t18.prototype.resume = function() {
        return this.alpha(0.1);
      }, t18.prototype.stop = function() {
        return this.alpha(0);
      }, t18.prototype.prepareEdgeRouting = function(t19) {
        void 0 === t19 && (t19 = 0), this._visibilityGraph = new u10.TangentVisibilityGraph(this._nodes.map(function(e23) {
          return e23.bounds.inflate(-t19).vertices();
        }));
      }, t18.prototype.routeEdge = function(t19, e23, n14) {
        void 0 === e23 && (e23 = 5);
        var r11 = [], i11 = new u10.TangentVisibilityGraph(this._visibilityGraph.P, { V: this._visibilityGraph.V, E: this._visibilityGraph.E }), o14 = { x: t19.source.x, y: t19.source.y }, h11 = { x: t19.target.x, y: t19.target.y }, c11 = i11.addPoint(o14, t19.source.index), p10 = i11.addPoint(h11, t19.target.index);
        i11.addEdgeIfVisible(o14, h11, t19.source.index, t19.target.index), void 0 !== n14 && n14(i11);
        var f12 = new a10.Calculator(i11.V.length, i11.E, function(t20) {
          return t20.source.id;
        }, function(t20) {
          return t20.target.id;
        }, function(t20) {
          return t20.length();
        }).PathFromNodeToNode(c11.id, p10.id);
        if (1 === f12.length || f12.length === i11.V.length) {
          var l11 = s11.makeEdgeBetween(t19.source.innerBounds, t19.target.innerBounds, e23);
          r11 = [l11.sourceIntersection, l11.arrowStart];
        } else {
          for (var d12 = f12.length - 2, g9 = i11.V[f12[d12]].p, v12 = i11.V[f12[0]].p, y10 = (r11 = [t19.source.innerBounds.rayIntersection(g9.x, g9.y)], d12); y10 >= 0; --y10)
            r11.push(i11.V[f12[y10]].p);
          r11.push(s11.makeEdgeTo(v12, t19.target.innerBounds, e23));
        }
        return r11;
      }, t18.getSourceIndex = function(t19) {
        return "number" == typeof t19.source ? t19.source : t19.source.index;
      }, t18.getTargetIndex = function(t19) {
        return "number" == typeof t19.target ? t19.target : t19.target.index;
      }, t18.linkId = function(e23) {
        return t18.getSourceIndex(e23) + "-" + t18.getTargetIndex(e23);
      }, t18.dragStart = function(e23) {
        c10(e23) ? t18.storeOffset(e23, t18.dragOrigin(e23)) : (t18.stopNode(e23), e23.fixed |= 2);
      }, t18.stopNode = function(t19) {
        t19.px = t19.x, t19.py = t19.y;
      }, t18.storeOffset = function(e23, n14) {
        void 0 !== e23.leaves && e23.leaves.forEach(function(e24) {
          e24.fixed |= 2, t18.stopNode(e24), e24._dragGroupOffsetX = e24.x - n14.x, e24._dragGroupOffsetY = e24.y - n14.y;
        }), void 0 !== e23.groups && e23.groups.forEach(function(e24) {
          return t18.storeOffset(e24, n14);
        });
      }, t18.dragOrigin = function(t19) {
        return c10(t19) ? { x: t19.bounds.cx(), y: t19.bounds.cy() } : t19;
      }, t18.drag = function(e23, n14) {
        c10(e23) ? (void 0 !== e23.leaves && e23.leaves.forEach(function(t19) {
          e23.bounds.setXCentre(n14.x), e23.bounds.setYCentre(n14.y), t19.px = t19._dragGroupOffsetX + n14.x, t19.py = t19._dragGroupOffsetY + n14.y;
        }), void 0 !== e23.groups && e23.groups.forEach(function(e24) {
          return t18.drag(e24, n14);
        })) : (e23.px = n14.x, e23.py = n14.y);
      }, t18.dragEnd = function(e23) {
        c10(e23) ? (void 0 !== e23.leaves && e23.leaves.forEach(function(e24) {
          t18.dragEnd(e24), delete e24._dragGroupOffsetX, delete e24._dragGroupOffsetY;
        }), void 0 !== e23.groups && e23.groups.forEach(t18.dragEnd)) : e23.fixed &= -7;
      }, t18.mouseOver = function(t19) {
        t19.fixed |= 4, t19.px = t19.x, t19.py = t19.y;
      }, t18.mouseOut = function(t19) {
        t19.fixed &= -5;
      }, t18;
    }();
    t17.Layout = f11;
  }(r6);
  var Gt5 = t11 && t11.__extends || function() {
    var t17 = function(e22, n13) {
      return t17 = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function(t18, e23) {
        t18.__proto__ = e23;
      } || function(t18, e23) {
        for (var n14 in e23)
          e23.hasOwnProperty(n14) && (t18[n14] = e23[n14]);
      }, t17(e22, n13);
    };
    return function(e22, n13) {
      function r10() {
        this.constructor = e22;
      }
      t17(e22, n13), e22.prototype = null === n13 ? Object.create(n13) : (r10.prototype = n13.prototype, new r10());
    };
  }();
  Object.defineProperty(n8, "__esModule", { value: true });
  var Vt5 = r6;
  var Dt5 = function(t17) {
    function e22(e23) {
      var n13 = t17.call(this) || this, r10 = e23;
      return r10.trigger && (n13.trigger = r10.trigger), r10.kick && (n13.kick = r10.kick), r10.drag && (n13.drag = r10.drag), r10.on && (n13.on = r10.on), n13.dragstart = n13.dragStart = Vt5.Layout.dragStart, n13.dragend = n13.dragEnd = Vt5.Layout.dragEnd, n13;
    }
    return Gt5(e22, t17), e22.prototype.trigger = function(t18) {
    }, e22.prototype.kick = function() {
    }, e22.prototype.drag = function() {
    }, e22.prototype.on = function(t18, e23) {
      return this;
    }, e22;
  }(Vt5.Layout);
  n8.LayoutAdaptor = Dt5, n8.adaptor = function(t17) {
    return new Dt5(t17);
  };
  var jt5 = {};
  var Bt5 = {};
  var Rt5 = t11 && t11.__extends || function() {
    var t17 = function(e22, n13) {
      return t17 = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function(t18, e23) {
        t18.__proto__ = e23;
      } || function(t18, e23) {
        for (var n14 in e23)
          e23.hasOwnProperty(n14) && (t18[n14] = e23[n14]);
      }, t17(e22, n13);
    };
    return function(e22, n13) {
      function r10() {
        this.constructor = e22;
      }
      t17(e22, n13), e22.prototype = null === n13 ? Object.create(n13) : (r10.prototype = n13.prototype, new r10());
    };
  }();
  Object.defineProperty(Bt5, "__esModule", { value: true });
  var Xt5 = r6;
  var zt5 = function(t17) {
    function e22() {
      var e23 = t17.call(this) || this;
      e23.event = d3.dispatch(Xt5.EventType[Xt5.EventType.start], Xt5.EventType[Xt5.EventType.tick], Xt5.EventType[Xt5.EventType.end]);
      var n13 = e23;
      return e23.drag = function() {
        if (!t18)
          var t18 = d3.behavior.drag().origin(Xt5.Layout.dragOrigin).on("dragstart.d3adaptor", Xt5.Layout.dragStart).on("drag.d3adaptor", function(t19) {
            Xt5.Layout.drag(t19, d3.event), n13.resume();
          }).on("dragend.d3adaptor", Xt5.Layout.dragEnd);
        if (!arguments.length)
          return t18;
        this.call(t18);
      }, e23;
    }
    return Rt5(e22, t17), e22.prototype.trigger = function(t18) {
      var e23 = { type: Xt5.EventType[t18.type], alpha: t18.alpha, stress: t18.stress };
      this.event[e23.type](e23);
    }, e22.prototype.kick = function() {
      var e23 = this;
      d3.timer(function() {
        return t17.prototype.tick.call(e23);
      });
    }, e22.prototype.on = function(t18, e23) {
      return "string" == typeof t18 ? this.event.on(t18, e23) : this.event.on(Xt5.EventType[t18], e23), this;
    }, e22;
  }(Xt5.Layout);
  Bt5.D3StyleLayoutAdaptor = zt5, Bt5.d3adaptor = function() {
    return new zt5();
  };
  var Yt5 = {};
  var qt5 = t11 && t11.__extends || function() {
    var t17 = function(e22, n13) {
      return t17 = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function(t18, e23) {
        t18.__proto__ = e23;
      } || function(t18, e23) {
        for (var n14 in e23)
          e23.hasOwnProperty(n14) && (t18[n14] = e23[n14]);
      }, t17(e22, n13);
    };
    return function(e22, n13) {
      function r10() {
        this.constructor = e22;
      }
      t17(e22, n13), e22.prototype = null === n13 ? Object.create(n13) : (r10.prototype = n13.prototype, new r10());
    };
  }();
  Object.defineProperty(Yt5, "__esModule", { value: true });
  var Ft5 = r6;
  var Ht5 = function(t17) {
    function e22(e23) {
      var n13 = t17.call(this) || this;
      n13.d3Context = e23, n13.event = e23.dispatch(Ft5.EventType[Ft5.EventType.start], Ft5.EventType[Ft5.EventType.tick], Ft5.EventType[Ft5.EventType.end]);
      var r10 = n13;
      return n13.drag = function() {
        if (!t18)
          var t18 = e23.drag().subject(Ft5.Layout.dragOrigin).on("start.d3adaptor", Ft5.Layout.dragStart).on("drag.d3adaptor", function(t19) {
            Ft5.Layout.drag(t19, e23.event), r10.resume();
          }).on("end.d3adaptor", Ft5.Layout.dragEnd);
        if (!arguments.length)
          return t18;
        arguments[0].call(t18);
      }, n13;
    }
    return qt5(e22, t17), e22.prototype.trigger = function(t18) {
      var e23 = { type: Ft5.EventType[t18.type], alpha: t18.alpha, stress: t18.stress };
      this.event.call(e23.type, e23);
    }, e22.prototype.kick = function() {
      var e23 = this, n13 = this.d3Context.timer(function() {
        return t17.prototype.tick.call(e23) && n13.stop();
      });
    }, e22.prototype.on = function(t18, e23) {
      return "string" == typeof t18 ? this.event.on(t18, e23) : this.event.on(Ft5.EventType[t18], e23), this;
    }, e22;
  }(Ft5.Layout);
  Yt5.D3StyleLayoutAdaptor = Ht5, Object.defineProperty(jt5, "__esModule", { value: true });
  var Ut5 = Bt5;
  var Wt5 = Yt5;
  jt5.d3adaptor = function(t17) {
    return !t17 || function(t18) {
      var e22 = /^3\./;
      return t18.version && null !== t18.version.match(e22);
    }(t17) ? new Ut5.D3StyleLayoutAdaptor() : new Wt5.D3StyleLayoutAdaptor(t17);
  };
  var Kt5 = {};
  Object.defineProperty(Kt5, "__esModule", { value: true });
  var Qt5 = m8;
  var Zt5 = b7;
  var Jt5 = tt5;
  var $t5 = function(t17, e22, n13) {
    this.id = t17, this.rect = e22, this.children = n13, this.leaf = void 0 === n13 || 0 === n13.length;
  };
  Kt5.NodeWrapper = $t5;
  var te2 = function(t17, e22, n13, r10, i11) {
    void 0 === r10 && (r10 = null), void 0 === i11 && (i11 = null), this.id = t17, this.x = e22, this.y = n13, this.node = r10, this.line = i11;
  };
  Kt5.Vert = te2;
  var ee2 = function() {
    function t17(e22, n13) {
      this.s = e22, this.t = n13;
      var r10 = t17.findMatch(e22, n13), i11 = n13.slice(0).reverse(), o13 = t17.findMatch(e22, i11);
      r10.length >= o13.length ? (this.length = r10.length, this.si = r10.si, this.ti = r10.ti, this.reversed = false) : (this.length = o13.length, this.si = o13.si, this.ti = n13.length - o13.ti - o13.length, this.reversed = true);
    }
    return t17.findMatch = function(t18, e22) {
      for (var n13 = t18.length, r10 = e22.length, i11 = { length: 0, si: -1, ti: -1 }, o13 = new Array(n13), s11 = 0; s11 < n13; s11++) {
        o13[s11] = new Array(r10);
        for (var a10 = 0; a10 < r10; a10++)
          if (t18[s11] === e22[a10]) {
            var u10 = o13[s11][a10] = 0 === s11 || 0 === a10 ? 1 : o13[s11 - 1][a10 - 1] + 1;
            u10 > i11.length && (i11.length = u10, i11.si = s11 - u10 + 1, i11.ti = a10 - u10 + 1);
          } else
            o13[s11][a10] = 0;
      }
      return i11;
    }, t17.prototype.getSequence = function() {
      return this.length >= 0 ? this.s.slice(this.si, this.si + this.length) : [];
    }, t17;
  }();
  Kt5.LongestCommonSubsequence = ee2;
  var ne2 = function() {
    function t17(t18, e22, n13) {
      var r10 = this;
      void 0 === n13 && (n13 = 12), this.originalnodes = t18, this.groupPadding = n13, this.leaves = null, this.nodes = t18.map(function(t19, n14) {
        return new $t5(n14, e22.getBounds(t19), e22.getChildren(t19));
      }), this.leaves = this.nodes.filter(function(t19) {
        return t19.leaf;
      }), this.groups = this.nodes.filter(function(t19) {
        return !t19.leaf;
      }), this.cols = this.getGridLines("x"), this.rows = this.getGridLines("y"), this.groups.forEach(function(t19) {
        return t19.children.forEach(function(e23) {
          return r10.nodes[e23].parent = t19;
        });
      }), this.root = { children: [] }, this.nodes.forEach(function(t19) {
        void 0 === t19.parent && (t19.parent = r10.root, r10.root.children.push(t19.id)), t19.ports = [];
      }), this.backToFront = this.nodes.slice(0), this.backToFront.sort(function(t19, e23) {
        return r10.getDepth(t19) - r10.getDepth(e23);
      }), this.backToFront.slice(0).reverse().filter(function(t19) {
        return !t19.leaf;
      }).forEach(function(t19) {
        var e23 = Qt5.Rectangle.empty();
        t19.children.forEach(function(t20) {
          return e23 = e23.union(r10.nodes[t20].rect);
        }), t19.rect = e23.inflate(r10.groupPadding);
      });
      var i11 = this.midPoints(this.cols.map(function(t19) {
        return t19.pos;
      })), o13 = this.midPoints(this.rows.map(function(t19) {
        return t19.pos;
      })), s11 = i11[0], a10 = i11[i11.length - 1], u10 = o13[0], h10 = o13[o13.length - 1], c10 = this.rows.map(function(t19) {
        return { x1: s11, x2: a10, y1: t19.pos, y2: t19.pos };
      }).concat(o13.map(function(t19) {
        return { x1: s11, x2: a10, y1: t19, y2: t19 };
      })), p10 = this.cols.map(function(t19) {
        return { x1: t19.pos, x2: t19.pos, y1: u10, y2: h10 };
      }).concat(i11.map(function(t19) {
        return { x1: t19, x2: t19, y1: u10, y2: h10 };
      })), f11 = c10.concat(p10);
      f11.forEach(function(t19) {
        return t19.verts = [];
      }), this.verts = [], this.edges = [], c10.forEach(function(t19) {
        return p10.forEach(function(e23) {
          var n14 = new te2(r10.verts.length, e23.x1, t19.y1);
          t19.verts.push(n14), e23.verts.push(n14), r10.verts.push(n14);
          for (var i12 = r10.backToFront.length; i12-- > 0; ) {
            var o14 = r10.backToFront[i12], s12 = o14.rect, a11 = Math.abs(n14.x - s12.cx()), u11 = Math.abs(n14.y - s12.cy());
            if (a11 < s12.width() / 2 && u11 < s12.height() / 2) {
              n14.node = o14;
              break;
            }
          }
        });
      }), f11.forEach(function(t19, e23) {
        r10.nodes.forEach(function(e24, n15) {
          e24.rect.lineIntersections(t19.x1, t19.y1, t19.x2, t19.y2).forEach(function(n16, i13) {
            var o15 = new te2(r10.verts.length, n16.x, n16.y, e24, t19);
            r10.verts.push(o15), t19.verts.push(o15), e24.ports.push(o15);
          });
        });
        var n14 = Math.abs(t19.y1 - t19.y2) < 0.1, i12 = function(t20, e24) {
          return n14 ? e24.x - t20.x : e24.y - t20.y;
        };
        t19.verts.sort(i12);
        for (var o14 = 1; o14 < t19.verts.length; o14++) {
          var s12 = t19.verts[o14 - 1], a11 = t19.verts[o14];
          s12.node && s12.node === a11.node && s12.node.leaf || r10.edges.push({ source: s12.id, target: a11.id, length: Math.abs(i12(s12, a11)) });
        }
      });
    }
    return t17.prototype.avg = function(t18) {
      return t18.reduce(function(t19, e22) {
        return t19 + e22;
      }) / t18.length;
    }, t17.prototype.getGridLines = function(t18) {
      for (var e22 = [], n13 = this.leaves.slice(0, this.leaves.length); n13.length > 0; ) {
        var r10 = n13.filter(function(e23) {
          return e23.rect["overlap" + t18.toUpperCase()](n13[0].rect);
        }), i11 = { nodes: r10, pos: this.avg(r10.map(function(e23) {
          return e23.rect["c" + t18]();
        })) };
        e22.push(i11), i11.nodes.forEach(function(t19) {
          return n13.splice(n13.indexOf(t19), 1);
        });
      }
      return e22.sort(function(t19, e23) {
        return t19.pos - e23.pos;
      }), e22;
    }, t17.prototype.getDepth = function(t18) {
      for (var e22 = 0; t18.parent !== this.root; )
        e22++, t18 = t18.parent;
      return e22;
    }, t17.prototype.midPoints = function(t18) {
      for (var e22 = t18[1] - t18[0], n13 = [t18[0] - e22 / 2], r10 = 1; r10 < t18.length; r10++)
        n13.push((t18[r10] + t18[r10 - 1]) / 2);
      return n13.push(t18[t18.length - 1] + e22 / 2), n13;
    }, t17.prototype.findLineage = function(t18) {
      var e22 = [t18];
      do {
        t18 = t18.parent, e22.push(t18);
      } while (t18 !== this.root);
      return e22.reverse();
    }, t17.prototype.findAncestorPathBetween = function(t18, e22) {
      for (var n13 = this.findLineage(t18), r10 = this.findLineage(e22), i11 = 0; n13[i11] === r10[i11]; )
        i11++;
      return { commonAncestor: n13[i11 - 1], lineages: n13.slice(i11).concat(r10.slice(i11)) };
    }, t17.prototype.siblingObstacles = function(t18, e22) {
      var n13 = this, r10 = this.findAncestorPathBetween(t18, e22), i11 = {};
      r10.lineages.forEach(function(t19) {
        return i11[t19.id] = {};
      });
      var o13 = r10.commonAncestor.children.filter(function(t19) {
        return !(t19 in i11);
      });
      return r10.lineages.filter(function(t19) {
        return t19.parent !== r10.commonAncestor;
      }).forEach(function(t19) {
        return o13 = o13.concat(t19.parent.children.filter(function(e23) {
          return e23 !== t19.id;
        }));
      }), o13.map(function(t19) {
        return n13.nodes[t19];
      });
    }, t17.getSegmentSets = function(t18, e22, n13) {
      for (var r10 = [], i11 = 0; i11 < t18.length; i11++)
        for (var o13 = t18[i11], s11 = 0; s11 < o13.length; s11++) {
          (p10 = o13[s11]).edgeid = i11, p10.i = s11;
          var a10 = p10[1][e22] - p10[0][e22];
          Math.abs(a10) < 0.1 && r10.push(p10);
        }
      r10.sort(function(t19, n14) {
        return t19[0][e22] - n14[0][e22];
      });
      for (var u10 = [], h10 = null, c10 = 0; c10 < r10.length; c10++) {
        var p10 = r10[c10];
        (!h10 || Math.abs(p10[0][e22] - h10.pos) > 0.1) && (h10 = { pos: p10[0][e22], segments: [] }, u10.push(h10)), h10.segments.push(p10);
      }
      return u10;
    }, t17.nudgeSegs = function(t18, e22, n13, r10, i11, o13) {
      var s11 = r10.length;
      if (!(s11 <= 1)) {
        for (var a10 = r10.map(function(e23) {
          return new Zt5.Variable(e23[0][t18]);
        }), u10 = [], h10 = 0; h10 < s11; h10++)
          for (var c10 = 0; c10 < s11; c10++)
            if (h10 !== c10) {
              var p10 = r10[h10], f11 = r10[c10], l11 = p10.edgeid, d12 = f11.edgeid, g9 = -1, v12 = -1;
              "x" == t18 ? i11(l11, d12) && (p10[0][e22] < p10[1][e22] ? (g9 = c10, v12 = h10) : (g9 = h10, v12 = c10)) : i11(l11, d12) && (p10[0][e22] < p10[1][e22] ? (g9 = h10, v12 = c10) : (g9 = c10, v12 = h10)), g9 >= 0 && u10.push(new Zt5.Constraint(a10[g9], a10[v12], o13));
            }
        new Zt5.Solver(a10, u10).solve(), a10.forEach(function(e23, i12) {
          var o14 = r10[i12], s12 = e23.position();
          o14[0][t18] = o14[1][t18] = s12;
          var a11 = n13[o14.edgeid];
          o14.i > 0 && (a11[o14.i - 1][1][t18] = s12), o14.i < a11.length - 1 && (a11[o14.i + 1][0][t18] = s12);
        });
      }
    }, t17.nudgeSegments = function(e22, n13, r10, i11, o13) {
      for (var s11 = t17.getSegmentSets(e22, n13, r10), a10 = 0; a10 < s11.length; a10++) {
        for (var u10 = s11[a10], h10 = [], c10 = 0; c10 < u10.segments.length; c10++) {
          var p10 = u10.segments[c10];
          h10.push({ type: 0, s: p10, pos: Math.min(p10[0][r10], p10[1][r10]) }), h10.push({ type: 1, s: p10, pos: Math.max(p10[0][r10], p10[1][r10]) });
        }
        h10.sort(function(t18, e23) {
          return t18.pos - e23.pos + t18.type - e23.type;
        });
        var f11 = [], l11 = 0;
        h10.forEach(function(s12) {
          0 === s12.type ? (f11.push(s12.s), l11++) : l11--, 0 == l11 && (t17.nudgeSegs(n13, r10, e22, f11, i11, o13), f11 = []);
        });
      }
    }, t17.prototype.routeEdges = function(e22, n13, r10, i11) {
      var o13 = this, s11 = e22.map(function(t18) {
        return o13.route(r10(t18), i11(t18));
      }), a10 = t17.orderEdges(s11), u10 = s11.map(function(e23) {
        return t17.makeSegments(e23);
      });
      return t17.nudgeSegments(u10, "x", "y", a10, n13), t17.nudgeSegments(u10, "y", "x", a10, n13), t17.unreverseEdges(u10, s11), u10;
    }, t17.unreverseEdges = function(t18, e22) {
      t18.forEach(function(t19, n13) {
        e22[n13].reversed && (t19.reverse(), t19.forEach(function(t20) {
          t20.reverse();
        }));
      });
    }, t17.angleBetween2Lines = function(t18, e22) {
      var n13 = Math.atan2(t18[0].y - t18[1].y, t18[0].x - t18[1].x), r10 = Math.atan2(e22[0].y - e22[1].y, e22[0].x - e22[1].x), i11 = n13 - r10;
      return (i11 > Math.PI || i11 < -Math.PI) && (i11 = r10 - n13), i11;
    }, t17.isLeft = function(t18, e22, n13) {
      return (e22.x - t18.x) * (n13.y - t18.y) - (e22.y - t18.y) * (n13.x - t18.x) <= 0;
    }, t17.getOrder = function(t18) {
      for (var e22 = {}, n13 = 0; n13 < t18.length; n13++) {
        var r10 = t18[n13];
        void 0 === e22[r10.l] && (e22[r10.l] = {}), e22[r10.l][r10.r] = true;
      }
      return function(t19, n14) {
        return void 0 !== e22[t19] && e22[t19][n14];
      };
    }, t17.orderEdges = function(e22) {
      for (var n13 = [], r10 = 0; r10 < e22.length - 1; r10++)
        for (var i11 = r10 + 1; i11 < e22.length; i11++) {
          var o13, s11, a10, u10 = e22[r10], h10 = e22[i11], c10 = new ee2(u10, h10);
          0 !== c10.length && (c10.reversed && (h10.reverse(), h10.reversed = true, c10 = new ee2(u10, h10)), (c10.si <= 0 || c10.ti <= 0) && (c10.si + c10.length >= u10.length || c10.ti + c10.length >= h10.length) ? n13.push({ l: r10, r: i11 }) : (c10.si + c10.length >= u10.length || c10.ti + c10.length >= h10.length ? (o13 = u10[c10.si + 1], a10 = u10[c10.si - 1], s11 = h10[c10.ti - 1]) : (o13 = u10[c10.si + c10.length - 2], s11 = u10[c10.si + c10.length], a10 = h10[c10.ti + c10.length]), t17.isLeft(o13, s11, a10) ? n13.push({ l: i11, r: r10 }) : n13.push({ l: r10, r: i11 })));
        }
      return t17.getOrder(n13);
    }, t17.makeSegments = function(t18) {
      function e22(t19) {
        return { x: t19.x, y: t19.y };
      }
      for (var n13 = function(t19, e23, n14) {
        return Math.abs((e23.x - t19.x) * (n14.y - t19.y) - (e23.y - t19.y) * (n14.x - t19.x)) < 1e-3;
      }, r10 = [], i11 = e22(t18[0]), o13 = 1; o13 < t18.length; o13++) {
        var s11 = e22(t18[o13]), a10 = o13 < t18.length - 1 ? t18[o13 + 1] : null;
        a10 && n13(i11, s11, a10) || (r10.push([i11, s11]), i11 = s11);
      }
      return r10;
    }, t17.prototype.route = function(t18, e22) {
      var n13 = this, r10 = this.nodes[t18], i11 = this.nodes[e22];
      this.obstacles = this.siblingObstacles(r10, i11);
      var o13 = {};
      this.obstacles.forEach(function(t19) {
        return o13[t19.id] = t19;
      }), this.passableEdges = this.edges.filter(function(t19) {
        var e23 = n13.verts[t19.source], r11 = n13.verts[t19.target];
        return !(e23.node && e23.node.id in o13 || r11.node && r11.node.id in o13);
      });
      for (var s11 = 1; s11 < r10.ports.length; s11++) {
        var a10 = r10.ports[0].id, u10 = r10.ports[s11].id;
        this.passableEdges.push({ source: a10, target: u10, length: 0 });
      }
      for (s11 = 1; s11 < i11.ports.length; s11++) {
        a10 = i11.ports[0].id, u10 = i11.ports[s11].id;
        this.passableEdges.push({ source: a10, target: u10, length: 0 });
      }
      var h10 = new Jt5.Calculator(this.verts.length, this.passableEdges, function(t19) {
        return t19.source;
      }, function(t19) {
        return t19.target;
      }, function(t19) {
        return t19.length;
      }).PathFromNodeToNodeWithPrevCost(r10.ports[0].id, i11.ports[0].id, function(t19, e23, o14) {
        var s12 = n13.verts[t19], a11 = n13.verts[e23], u11 = n13.verts[o14], h11 = Math.abs(u11.x - s12.x), c11 = Math.abs(u11.y - s12.y);
        return s12.node === r10 && s12.node === a11.node || a11.node === i11 && a11.node === u11.node ? 0 : h11 > 1 && c11 > 1 ? 1e3 : 0;
      }), c10 = h10.reverse().map(function(t19) {
        return n13.verts[t19];
      });
      return c10.push(this.nodes[i11.id].ports[0]), c10.filter(function(t19, e23) {
        return !(e23 < c10.length - 1 && c10[e23 + 1].node === r10 && t19.node === r10 || e23 > 0 && t19.node === i11 && c10[e23 - 1].node === i11);
      });
    }, t17.getRoutePath = function(e22, n13, r10, i11) {
      var o13 = { routepath: "M " + e22[0][0].x + " " + e22[0][0].y + " ", arrowpath: "" };
      if (e22.length > 1)
        for (var s11 = 0; s11 < e22.length; s11++) {
          var a10 = (m12 = e22[s11])[1].x, u10 = m12[1].y, h10 = a10 - m12[0].x, c10 = u10 - m12[0].y;
          if (s11 < e22.length - 1) {
            Math.abs(h10) > 0 ? a10 -= h10 / Math.abs(h10) * n13 : u10 -= c10 / Math.abs(c10) * n13, o13.routepath += "L " + a10 + " " + u10 + " ";
            var p10 = e22[s11 + 1], f11 = p10[0].x, l11 = p10[0].y;
            h10 = p10[1].x - f11, c10 = p10[1].y - l11;
            var d12, g9, v12 = t17.angleBetween2Lines(m12, p10) < 0 ? 1 : 0;
            Math.abs(h10) > 0 ? (d12 = f11 + h10 / Math.abs(h10) * n13, g9 = l11) : (d12 = f11, g9 = l11 + c10 / Math.abs(c10) * n13);
            var y10 = Math.abs(d12 - a10), _7 = Math.abs(g9 - u10);
            o13.routepath += "A " + y10 + " " + _7 + " 0 0 " + v12 + " " + d12 + " " + g9 + " ";
          } else {
            var x11 = [a10, u10];
            Math.abs(h10) > 0 ? (b11 = [a10 -= h10 / Math.abs(h10) * i11, u10 + r10], k10 = [a10, u10 - r10]) : (b11 = [a10 + r10, u10 -= c10 / Math.abs(c10) * i11], k10 = [a10 - r10, u10]), o13.routepath += "L " + a10 + " " + u10 + " ", i11 > 0 && (o13.arrowpath = "M " + x11[0] + " " + x11[1] + " L " + b11[0] + " " + b11[1] + " L " + k10[0] + " " + k10[1]);
          }
        }
      else {
        var m12, b11, k10;
        a10 = (m12 = e22[0])[1].x, u10 = m12[1].y, h10 = a10 - m12[0].x, c10 = u10 - m12[0].y, x11 = [a10, u10];
        Math.abs(h10) > 0 ? (b11 = [a10 -= h10 / Math.abs(h10) * i11, u10 + r10], k10 = [a10, u10 - r10]) : (b11 = [a10 + r10, u10 -= c10 / Math.abs(c10) * i11], k10 = [a10 - r10, u10]), o13.routepath += "L " + a10 + " " + u10 + " ", i11 > 0 && (o13.arrowpath = "M " + x11[0] + " " + x11[1] + " L " + b11[0] + " " + b11[1] + " L " + k10[0] + " " + k10[1]);
      }
      return o13;
    }, t17;
  }();
  Kt5.GridRouter = ne2;
  var re2 = {};
  Object.defineProperty(re2, "__esModule", { value: true });
  var ie2 = tt5;
  var oe2 = v7;
  var se2 = m8;
  var ae2 = p7;
  var ue2 = function() {
    function t17(t18, e22) {
      this.source = t18, this.target = e22;
    }
    return t17.prototype.actualLength = function(t18) {
      var e22 = this;
      return Math.sqrt(t18.reduce(function(t19, n13) {
        var r10 = n13[e22.target] - n13[e22.source];
        return t19 + r10 * r10;
      }, 0));
    }, t17;
  }();
  re2.Link3D = ue2;
  var he2 = function(t17, e22, n13) {
    void 0 === t17 && (t17 = 0), void 0 === e22 && (e22 = 0), void 0 === n13 && (n13 = 0), this.x = t17, this.y = e22, this.z = n13;
  };
  re2.Node3D = he2;
  var ce2 = function() {
    function t17(e22, n13, r10) {
      var i11 = this;
      void 0 === r10 && (r10 = 1), this.nodes = e22, this.links = n13, this.idealLinkLength = r10, this.constraints = null, this.useJaccardLinkLengths = true, this.result = new Array(t17.k);
      for (var o13 = 0; o13 < t17.k; ++o13)
        this.result[o13] = new Array(e22.length);
      e22.forEach(function(e23, n14) {
        for (var r11 = 0, o14 = t17.dims; r11 < o14.length; r11++) {
          var s11 = o14[r11];
          void 0 === e23[s11] && (e23[s11] = Math.random());
        }
        i11.result[0][n14] = e23.x, i11.result[1][n14] = e23.y, i11.result[2][n14] = e23.z;
      });
    }
    return t17.prototype.linkLength = function(t18) {
      return t18.actualLength(this.result);
    }, t17.prototype.start = function(t18) {
      var e22 = this;
      void 0 === t18 && (t18 = 100);
      var n13 = this.nodes.length, r10 = new pe2();
      this.useJaccardLinkLengths && ae2.jaccardLinkLengths(this.links, r10, 1.5), this.links.forEach(function(t19) {
        return t19.length *= e22.idealLinkLength;
      });
      var i11 = new ie2.Calculator(n13, this.links, function(t19) {
        return t19.source;
      }, function(t19) {
        return t19.target;
      }, function(t19) {
        return t19.length;
      }).DistanceMatrix(), o13 = oe2.Descent.createSquareMatrix(n13, function(t19, e23) {
        return i11[t19][e23];
      }), s11 = oe2.Descent.createSquareMatrix(n13, function() {
        return 2;
      });
      this.links.forEach(function(t19) {
        var e23 = t19.source, n14 = t19.target;
        return s11[e23][n14] = s11[n14][e23] = 1;
      }), this.descent = new oe2.Descent(this.result, o13), this.descent.threshold = 1e-3, this.descent.G = s11, this.constraints && (this.descent.project = new se2.Projection(this.nodes, null, null, this.constraints).projectFunctions());
      for (var a10 = 0; a10 < this.nodes.length; a10++) {
        var u10 = this.nodes[a10];
        u10.fixed && this.descent.locks.add(a10, [u10.x, u10.y, u10.z]);
      }
      return this.descent.run(t18), this;
    }, t17.prototype.tick = function() {
      this.descent.locks.clear();
      for (var t18 = 0; t18 < this.nodes.length; t18++) {
        var e22 = this.nodes[t18];
        e22.fixed && this.descent.locks.add(t18, [e22.x, e22.y, e22.z]);
      }
      return this.descent.rungeKutta();
    }, t17.dims = ["x", "y", "z"], t17.k = t17.dims.length, t17;
  }();
  re2.Layout3D = ce2;
  var pe2 = function() {
    function t17() {
    }
    return t17.prototype.getSourceIndex = function(t18) {
      return t18.source;
    }, t17.prototype.getTargetIndex = function(t18) {
      return t18.target;
    }, t17.prototype.getLength = function(t18) {
      return t18.length;
    }, t17.prototype.setLength = function(t18, e22) {
      t18.length = e22;
    }, t17;
  }();
  var fe2 = {};
  Object.defineProperty(fe2, "__esModule", { value: true });
  var le2 = r6;
  var de2 = Kt5;
  fe2.gridify = function(t17, e22, n13, r10) {
    t17.cola.start(0, 0, 0, 10, false);
    var i11 = function(t18, e23, n14, r11) {
      t18.forEach(function(t19) {
        t19.routerNode = { name: t19.name, bounds: t19.bounds.inflate(-n14) };
      }), e23.forEach(function(e24) {
        e24.routerNode = { bounds: e24.bounds.inflate(-r11), children: (void 0 !== e24.groups ? e24.groups.map(function(e25) {
          return t18.length + e25.id;
        }) : []).concat(void 0 !== e24.leaves ? e24.leaves.map(function(t19) {
          return t19.index;
        }) : []) };
      });
      var i12 = t18.concat(e23).map(function(t19, e24) {
        return t19.routerNode.id = e24, t19.routerNode;
      });
      return new de2.GridRouter(i12, { getChildren: function(t19) {
        return t19.children;
      }, getBounds: function(t19) {
        return t19.bounds;
      } }, n14 - r11);
    }(t17.cola.nodes(), t17.cola.groups(), n13, r10);
    return i11.routeEdges(t17.powerGraph.powerEdges, e22, function(t18) {
      return t18.source.routerNode.id;
    }, function(t18) {
      return t18.target.routerNode.id;
    });
  }, fe2.powerGraphGridLayout = function(t17, e22, n13) {
    var r10;
    t17.nodes.forEach(function(t18, e23) {
      return t18.index = e23;
    }), new le2.Layout().avoidOverlaps(false).nodes(t17.nodes).links(t17.links).powerGraphGroups(function(t18) {
      (r10 = t18).groups.forEach(function(t19) {
        return t19.padding = n13;
      });
    });
    var i11 = t17.nodes.length, o13 = [], s11 = t17.nodes.slice(0);
    return s11.forEach(function(t18, e23) {
      return t18.index = e23;
    }), r10.groups.forEach(function(t18) {
      var e23 = t18.index = t18.id + i11;
      s11.push(t18), void 0 !== t18.leaves && t18.leaves.forEach(function(t19) {
        return o13.push({ source: e23, target: t19.index });
      }), void 0 !== t18.groups && t18.groups.forEach(function(t19) {
        return o13.push({ source: e23, target: t19.id + i11 });
      });
    }), r10.powerEdges.forEach(function(t18) {
      o13.push({ source: t18.source.index, target: t18.target.index });
    }), new le2.Layout().size(e22).nodes(s11).links(o13).avoidOverlaps(false).linkDistance(30).symmetricDiffLinkLengths(5).convergenceThreshold(1e-4).start(100, 0, 0, 0, false), { cola: new le2.Layout().convergenceThreshold(1e-3).size(e22).avoidOverlaps(true).nodes(t17.nodes).links(t17.links).groupCompactness(1e-4).linkDistance(30).symmetricDiffLinkLengths(5).powerGraphGroups(function(t18) {
      (r10 = t18).groups.forEach(function(t19) {
        t19.padding = n13;
      });
    }).start(50, 0, 100, 0, false), powerGraph: r10 };
  }, function(t17) {
    function e22(e23) {
      for (var n13 in e23)
        t17.hasOwnProperty(n13) || (t17[n13] = e23[n13]);
    }
    Object.defineProperty(t17, "__esModule", { value: true }), e22(n8), e22(jt5), e22(v7), e22(ht5), e22(Kt5), e22(Ct5), e22(r6), e22(re2), e22(p7), e22(i7), e22(et5), e22(S7), e22(m8), e22(tt5), e22(b7), e22(fe2);
  }(e16);
  var ge2 = e16.BiTangent;
  var ve2 = e16.BiTangents;
  var ye2 = e16.Block;
  var _e2 = e16.Blocks;
  var xe2 = e16.Calculator;
  var me2 = e16.Configuration;
  var be2 = e16.Constraint;
  var ke2 = e16.ConvexHull;
  var we2 = e16.Descent;
  var Ee2 = e16.EventType;
  var Pe2 = e16.GridRouter;
  var Le2 = e16.IndexedVariable;
  var Me2 = e16.Iterator;
  var Ae2 = e16.LLtangent_PolyPolyC;
  var Se2 = e16.LRtangent_PolyPolyC;
  var Oe2 = e16.Layout;
  var Ce2 = e16.Layout3D;
  var Ne2 = e16.LayoutAdaptor;
  var Ie2 = e16.LineSegment;
  var Te2 = e16.Link3D;
  var Ge2 = e16.LinkSets;
  var Ve2 = e16.Locks;
  var De2 = e16.LongestCommonSubsequence;
  var je2 = e16.Module;
  var Be2 = e16.ModuleSet;
  var Re2 = e16.Node3D;
  var Xe2 = e16.NodeWrapper;
  var ze2 = e16.PairingHeap;
  var Ye2 = e16.Point;
  var qe2 = e16.PolyPoint;
  var Fe2 = e16.PositionStats;
  var He2 = e16.PowerEdge;
  var Ue2 = e16.PriorityQueue;
  var We2 = e16.Projection;
  var Ke2 = e16.PseudoRandom;
  var Qe2 = e16.RBTree;
  var Ze2 = e16.RLtangent_PolyPolyC;
  var Je2 = e16.RRtangent_PolyPolyC;
  var $e2 = e16.Rectangle;
  var tn2 = e16.Solver;
  var en2 = e16.TVGPoint;
  var nn2 = e16.TangentVisibilityGraph;
  var rn2 = e16.TreeBase;
  var on2 = e16.Variable;
  var sn2 = e16.Vert;
  var an2 = e16.VisibilityEdge;
  var un2 = e16.VisibilityVertex;
  var hn2 = e16.__esModule;
  var cn2 = e16.adaptor;
  var pn2 = e16.applyPacking;
  var fn2 = e16.clockwiseRadialSweep;
  var ln2 = e16.computeGroupBounds;
  var dn2 = e16.d3adaptor;
  var gn2 = e16.generateDirectedEdgeConstraints;
  var vn2 = e16.generateXConstraints;
  var yn2 = e16.generateXGroupConstraints;
  var _n2 = e16.generateYConstraints;
  var xn2 = e16.generateYGroupConstraints;
  var mn2 = e16.getGroups;
  var bn2 = e16.gridify;
  var kn2 = e16.isLeft;
  var wn2 = e16.jaccardLinkLengths;
  var En2 = e16.makeEdgeBetween;
  var Pn2 = e16.makeEdgeTo;
  var Ln2 = e16.polysOverlap;
  var Mn2 = e16.powerGraphGridLayout;
  var An2 = e16.removeOverlapInOneDimension;
  var Sn2 = e16.removeOverlaps;
  var On2 = e16.separateGraphs;
  var Cn2 = e16.stronglyConnectedComponents;
  var Nn2 = e16.symmetricDiffLinkLengths;
  var In2 = e16.tangent_PolyPolyC;
  var Tn2 = e16.tangents;

  // http-url:https://cdn.jsdelivr.net/npm/cytoscape-cola@2.5.1/+esm
  var t12 = { exports: {} };
  var e17 = t12.exports = function(n13) {
    return function(n14) {
      var t17 = {};
      function e22(o13) {
        if (t17[o13])
          return t17[o13].exports;
        var i11 = t17[o13] = { i: o13, l: false, exports: {} };
        return n14[o13].call(i11.exports, i11, i11.exports, e22), i11.l = true, i11.exports;
      }
      return e22.m = n14, e22.c = t17, e22.i = function(n15) {
        return n15;
      }, e22.d = function(n15, t18, o13) {
        e22.o(n15, t18) || Object.defineProperty(n15, t18, { configurable: false, enumerable: true, get: o13 });
      }, e22.n = function(n15) {
        var t18 = n15 && n15.__esModule ? function() {
          return n15.default;
        } : function() {
          return n15;
        };
        return e22.d(t18, "a", t18), t18;
      }, e22.o = function(n15, t18) {
        return Object.prototype.hasOwnProperty.call(n15, t18);
      }, e22.p = "", e22(e22.s = 3);
    }([function(n14, t17, e22) {
      var o13 = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(n15) {
        return typeof n15;
      } : function(n15) {
        return n15 && "function" == typeof Symbol && n15.constructor === Symbol && n15 !== Symbol.prototype ? "symbol" : typeof n15;
      }, i11 = e22(1), r10 = e22(2), a10 = e22(5) || ("undefined" != typeof window ? window.cola : null), c10 = e22(4), u10 = function(n15) {
        return (void 0 === n15 ? "undefined" : o13(n15)) === o13(0);
      }, f11 = function() {
      }, s11 = function(n15, t18) {
        var e23;
        return null != (e23 = n15) && (void 0 === e23 ? "undefined" : o13(e23)) === o13(function() {
        }) ? n15.apply(t18, [t18]) : n15;
      };
      function d12(n15) {
        this.options = i11({}, r10, n15);
      }
      d12.prototype.run = function() {
        var n15 = this, t18 = this.options;
        n15.manuallyStopped = false;
        var e23 = t18.cy, i12 = t18.eles, r11 = i12.nodes(), d13 = i12.edges(), l11 = false, p10 = r11.filter(function(n16) {
          return n16.isParent();
        }), y10 = r11.subtract(p10), h10 = t18.boundingBox || { x1: 0, y1: 0, w: e23.width(), h: e23.height() };
        void 0 === h10.x2 && (h10.x2 = h10.x1 + h10.w), void 0 === h10.w && (h10.w = h10.x2 - h10.x1), void 0 === h10.y2 && (h10.y2 = h10.y1 + h10.h), void 0 === h10.h && (h10.h = h10.y2 - h10.y1);
        var g9 = function() {
          for (var n16 = 0; n16 < r11.length; n16++) {
            var o14 = r11[n16], i13 = o14.layoutDimensions(t18), a11 = o14.scratch("cola");
            if (!a11.updatedDims) {
              var c11 = s11(t18.nodeSpacing, o14);
              a11.width = i13.w + 2 * c11, a11.height = i13.h + 2 * c11;
            }
          }
          r11.positions(function(n17) {
            var t19 = n17.scratch().cola, e24 = void 0;
            return !n17.grabbed() && y10.contains(n17) && (e24 = { x: h10.x1 + t19.x, y: h10.y1 + t19.y }, u10(e24.x) && u10(e24.y) || (e24 = void 0)), e24;
          }), r11.updateCompoundBounds(), l11 || (v12(), l11 = true), t18.fit && e23.fit(t18.padding);
        }, m12 = function() {
          t18.ungrabifyWhileSimulating && w10.grabify(), e23.off("destroy", S8), r11.off("grab free position", k10), r11.off("lock unlock", L10), n15.one("layoutstop", t18.stop), n15.trigger({ type: "layoutstop", layout: n15 });
        }, v12 = function() {
          n15.one("layoutready", t18.ready), n15.trigger({ type: "layoutready", layout: n15 });
        }, x11 = t18.refresh;
        x11 = t18.refresh < 0 ? 1 : Math.max(1, x11);
        var b11 = n15.adaptor = a10.adaptor({ trigger: function(n16) {
          var e24 = a10.EventType ? a10.EventType.tick : null, o14 = a10.EventType ? a10.EventType.end : null;
          switch (n16.type) {
            case "tick":
            case e24:
              t18.animate && g9();
              break;
            case "end":
            case o14:
              g9(), t18.infinite || m12();
          }
        }, kick: function() {
          var e24 = true, o14 = function() {
            if (n15.manuallyStopped)
              return m12(), true;
            var o15 = b11.tick();
            return t18.infinite || e24 || b11.convergenceThreshold(t18.convergenceThreshold), e24 = false, o15 && t18.infinite && b11.resume(), o15;
          };
          if (t18.animate)
            c10(function n16() {
              (function() {
                for (var n17 = void 0, t19 = 0; t19 < x11 && !n17; t19++)
                  n17 = n17 || o14();
                return n17;
              })() || c10(n16);
            });
          else
            for (; !o14(); )
              ;
        }, on: f11, drag: f11 });
        n15.adaptor = b11;
        var w10 = r11.filter(":grabbable");
        t18.ungrabifyWhileSimulating && w10.ungrabify();
        var S8 = void 0;
        e23.one("destroy", S8 = function() {
          n15.stop();
        });
        var k10 = void 0;
        r11.on("grab free position", k10 = function(n16) {
          var t19 = this, e24 = t19.scratch().cola, o14 = t19.position();
          if (n16.cyTarget === t19 || n16.target === t19)
            switch (n16.type) {
              case "grab":
                b11.dragstart(e24);
                break;
              case "free":
                b11.dragend(e24);
                break;
              case "position":
                e24.px === o14.x - h10.x1 && e24.py === o14.y - h10.y1 || (e24.px = o14.x - h10.x1, e24.py = o14.y - h10.y1);
            }
        });
        var L10 = void 0;
        r11.on("lock unlock", L10 = function() {
          var n16 = this, t19 = n16.scratch().cola;
          t19.fixed = n16.locked(), n16.locked() ? b11.dragstart(t19) : b11.dragend(t19);
        }), b11.nodes(y10.map(function(n16, e24) {
          var o14 = s11(t18.nodeSpacing, n16), i13 = n16.position(), r12 = n16.layoutDimensions(t18);
          return n16.scratch().cola = { x: t18.randomize && !n16.locked() || void 0 === i13.x ? Math.round(Math.random() * h10.w) : i13.x, y: t18.randomize && !n16.locked() || void 0 === i13.y ? Math.round(Math.random() * h10.h) : i13.y, width: r12.w + 2 * o14, height: r12.h + 2 * o14, index: e24, fixed: n16.locked() };
        }));
        var T9 = [];
        t18.alignment && (t18.alignment.vertical && t18.alignment.vertical.forEach(function(n16) {
          var t19 = [];
          n16.forEach(function(n17) {
            var e24 = n17.node.scratch().cola.index;
            t19.push({ node: e24, offset: n17.offset ? n17.offset : 0 });
          }), T9.push({ type: "alignment", axis: "x", offsets: t19 });
        }), t18.alignment.horizontal && t18.alignment.horizontal.forEach(function(n16) {
          var t19 = [];
          n16.forEach(function(n17) {
            var e24 = n17.node.scratch().cola.index;
            t19.push({ node: e24, offset: n17.offset ? n17.offset : 0 });
          }), T9.push({ type: "alignment", axis: "y", offsets: t19 });
        })), t18.gapInequalities && t18.gapInequalities.forEach(function(n16) {
          var t19 = n16.left.scratch().cola.index, e24 = n16.right.scratch().cola.index;
          T9.push({ axis: n16.axis, left: t19, right: e24, gap: n16.gap, equality: n16.equality });
        }), T9.length > 0 && b11.constraints(T9), b11.groups(p10.map(function(n16, e24) {
          var o14 = s11(t18.nodeSpacing, n16), i13 = function(t19) {
            return parseFloat(n16.style("padding-" + t19));
          }, r12 = i13("left") + o14, a11 = i13("right") + o14, c11 = i13("top") + o14, u11 = i13("bottom") + o14;
          return n16.scratch().cola = { index: e24, padding: Math.max(r12, a11, c11, u11), leaves: n16.children().intersection(y10).map(function(n17) {
            return n17[0].scratch().cola.index;
          }), fixed: n16.locked() }, n16;
        }).map(function(n16) {
          return n16.scratch().cola.groups = n16.children().intersection(p10).map(function(n17) {
            return n17.scratch().cola.index;
          }), n16.scratch().cola;
        }));
        var D7, E10 = void 0, I8 = void 0;
        if (null != t18.edgeLength ? (E10 = t18.edgeLength, I8 = "linkDistance") : null != t18.edgeSymDiffLength ? (E10 = t18.edgeSymDiffLength, I8 = "symmetricDiffLinkLengths") : null != t18.edgeJaccardLength ? (E10 = t18.edgeJaccardLength, I8 = "jaccardLinkLengths") : (E10 = 100, I8 = "linkDistance"), b11.links(d13.stdFilter(function(n16) {
          return y10.contains(n16.source()) && y10.contains(n16.target());
        }).map(function(n16) {
          var t19 = n16.scratch().cola = { source: n16.source()[0].scratch().cola.index, target: n16.target()[0].scratch().cola.index };
          return null != E10 && (t19.calcLength = s11(E10, n16)), t19;
        })), b11.size([h10.w, h10.h]), null != E10 && b11[I8](function(n16) {
          return n16.calcLength;
        }), t18.flow) {
          var O9 = void 0;
          (void 0 === (D7 = t18.flow) ? "undefined" : o13(D7)) === o13("") ? O9 = { axis: t18.flow, minSeparation: 50 } : u10(t18.flow) ? O9 = { axis: "y", minSeparation: t18.flow } : function(n16) {
            return null != n16 && (void 0 === n16 ? "undefined" : o13(n16)) === o13({});
          }(t18.flow) ? ((O9 = t18.flow).axis = O9.axis || "y", O9.minSeparation = null != O9.minSeparation ? O9.minSeparation : 50) : O9 = { axis: "y", minSeparation: 50 }, b11.flowLayout(O9.axis, O9.minSeparation);
        }
        return n15.trigger({ type: "layoutstart", layout: n15 }), b11.avoidOverlaps(t18.avoidOverlap).handleDisconnected(t18.handleDisconnected).start(t18.unconstrIter, t18.userConstIter, t18.allConstIter, void 0, void 0, t18.centerGraph), t18.infinite || setTimeout(function() {
          n15.manuallyStopped || b11.stop();
        }, t18.maxSimulationTime), this;
      }, d12.prototype.stop = function() {
        return this.adaptor && (this.manuallyStopped = true, this.adaptor.stop()), this;
      }, n14.exports = d12;
    }, function(n14, t17, e22) {
      n14.exports = null != Object.assign ? Object.assign.bind(Object) : function(n15) {
        for (var t18 = arguments.length, e23 = Array(t18 > 1 ? t18 - 1 : 0), o13 = 1; o13 < t18; o13++)
          e23[o13 - 1] = arguments[o13];
        return e23.filter(function(n16) {
          return null != n16;
        }).forEach(function(t19) {
          Object.keys(t19).forEach(function(e24) {
            return n15[e24] = t19[e24];
          });
        }), n15;
      };
    }, function(n14, t17, e22) {
      var o13 = { animate: true, refresh: 1, maxSimulationTime: 4e3, ungrabifyWhileSimulating: false, fit: true, padding: 30, boundingBox: void 0, nodeDimensionsIncludeLabels: false, ready: function() {
      }, stop: function() {
      }, randomize: false, avoidOverlap: true, handleDisconnected: true, convergenceThreshold: 0.01, nodeSpacing: function(n15) {
        return 10;
      }, flow: void 0, alignment: void 0, gapInequalities: void 0, centerGraph: true, edgeLength: void 0, edgeSymDiffLength: void 0, edgeJaccardLength: void 0, unconstrIter: void 0, userConstIter: void 0, allConstIter: void 0, infinite: false };
      n14.exports = o13;
    }, function(n14, t17, e22) {
      var o13 = e22(0), i11 = function(n15) {
        n15 && n15("layout", "cola", o13);
      };
      "undefined" != typeof cytoscape && i11(cytoscape), n14.exports = i11;
    }, function(n14, t17, e22) {
      var o13 = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(n15) {
        return typeof n15;
      } : function(n15) {
        return n15 && "function" == typeof Symbol && n15.constructor === Symbol && n15 !== Symbol.prototype ? "symbol" : typeof n15;
      }, i11 = void 0;
      i11 = "undefined" !== ("undefined" == typeof window ? "undefined" : o13(window)) ? window.requestAnimationFrame || window.webkitRequestAnimationFrame || window.mozRequestAnimationFrame || window.msRequestAnimationFrame || function(n15) {
        return setTimeout(n15, 16);
      } : function(n15) {
        n15();
      }, n14.exports = i11;
    }, function(t17, e22) {
      t17.exports = n13;
    }]);
  }(e16);

  // http-url:https://cdn.jsdelivr.net/npm/@floating-ui/utils@0.2.1/+esm
  var t13 = ["top", "right", "bottom", "left"];
  var n9 = ["start", "end"];
  var o9 = t13.reduce((t17, o13) => t17.concat(o13, o13 + "-" + n9[0], o13 + "-" + n9[1]), []);
  var f8 = { left: "right", right: "left", bottom: "top", top: "bottom" };
  var a7 = { start: "end", end: "start" };
  function h8(t17, n13) {
    return "function" == typeof t17 ? t17(n13) : t17;
  }
  function p8(t17) {
    return t17.split("-")[0];
  }
  function s8(t17) {
    return t17.split("-")[1];
  }
  function m9(t17) {
    return "x" === t17 ? "y" : "x";
  }
  function g8(t17) {
    return "y" === t17 ? "height" : "width";
  }
  function b8(t17) {
    return ["top", "bottom"].includes(p8(t17)) ? "y" : "x";
  }
  function d9(t17) {
    return m9(b8(t17));
  }
  function x8(t17, n13, o13) {
    void 0 === o13 && (o13 = false);
    const r10 = s8(t17), e22 = d9(t17), u10 = g8(e22);
    let i11 = "x" === e22 ? r10 === (o13 ? "end" : "start") ? "right" : "left" : "start" === r10 ? "bottom" : "top";
    return n13.reference[u10] > n13.floating[u10] && (i11 = v8(i11)), [i11, v8(i11)];
  }
  function y8(t17) {
    const n13 = v8(t17);
    return [M8(t17), n13, M8(n13)];
  }
  function M8(t17) {
    return t17.replace(/start|end/g, (t18) => a7[t18]);
  }
  function w8(t17, n13, o13, r10) {
    const e22 = s8(t17);
    let u10 = function(t18, n14, o14) {
      const r11 = ["left", "right"], e23 = ["right", "left"], u11 = ["top", "bottom"], i11 = ["bottom", "top"];
      switch (t18) {
        case "top":
        case "bottom":
          return o14 ? n14 ? e23 : r11 : n14 ? r11 : e23;
        case "left":
        case "right":
          return n14 ? u11 : i11;
        default:
          return [];
      }
    }(p8(t17), "start" === o13, r10);
    return e22 && (u10 = u10.map((t18) => t18 + "-" + e22), n13 && (u10 = u10.concat(u10.map(M8)))), u10;
  }
  function v8(t17) {
    return t17.replace(/left|right|bottom|top/g, (t18) => f8[t18]);
  }
  function j8(t17) {
    return { top: 0, right: 0, bottom: 0, left: 0, ...t17 };
  }
  function k7(t17) {
    return "number" != typeof t17 ? j8(t17) : { top: t17, right: t17, bottom: t17, left: t17 };
  }
  function q7(t17) {
    return { ...t17, top: t17.y, left: t17.x, right: t17.x + t17.width, bottom: t17.y + t17.height };
  }

  // http-url:https://cdn.jsdelivr.net/npm/@floating-ui/core@1.6.0/+esm
  function x9(e22, t17, n13) {
    let { reference: r10, floating: a10 } = e22;
    const s11 = b8(t17), c10 = d9(t17), m12 = g8(c10), u10 = p8(t17), d12 = "y" === s11, p10 = r10.x + r10.width / 2 - a10.width / 2, h10 = r10.y + r10.height / 2 - a10.height / 2, y10 = r10[m12] / 2 - a10[m12] / 2;
    let w10;
    switch (u10) {
      case "top":
        w10 = { x: p10, y: r10.y - a10.height };
        break;
      case "bottom":
        w10 = { x: p10, y: r10.y + r10.height };
        break;
      case "right":
        w10 = { x: r10.x + r10.width, y: h10 };
        break;
      case "left":
        w10 = { x: r10.x - a10.width, y: h10 };
        break;
      default:
        w10 = { x: r10.x, y: r10.y };
    }
    switch (s8(t17)) {
      case "start":
        w10[c10] -= y10 * (n13 && d12 ? -1 : 1);
        break;
      case "end":
        w10[c10] += y10 * (n13 && d12 ? -1 : 1);
    }
    return w10;
  }
  var v9 = async (e22, t17, n13) => {
    const { placement: i11 = "bottom", strategy: o13 = "absolute", middleware: r10 = [], platform: a10 } = n13, l11 = r10.filter(Boolean), s11 = await (null == a10.isRTL ? void 0 : a10.isRTL(t17));
    let c10 = await a10.getElementRects({ reference: e22, floating: t17, strategy: o13 }), { x: f11, y: m12 } = x9(c10, i11, s11), u10 = i11, d12 = {}, g9 = 0;
    for (let n14 = 0; n14 < l11.length; n14++) {
      const { name: r11, fn: p10 } = l11[n14], { x: h10, y: y10, data: w10, reset: v12 } = await p10({ x: f11, y: m12, initialPlacement: i11, placement: u10, strategy: o13, middlewareData: d12, rects: c10, platform: a10, elements: { reference: e22, floating: t17 } });
      f11 = null != h10 ? h10 : f11, m12 = null != y10 ? y10 : m12, d12 = { ...d12, [r11]: { ...d12[r11], ...w10 } }, v12 && g9 <= 50 && (g9++, "object" == typeof v12 && (v12.placement && (u10 = v12.placement), v12.rects && (c10 = true === v12.rects ? await a10.getElementRects({ reference: e22, floating: t17, strategy: o13 }) : v12.rects), { x: f11, y: m12 } = x9(c10, u10, s11)), n14 = -1);
    }
    return { x: f11, y: m12, placement: u10, strategy: o13, middlewareData: d12 };
  };
  async function b9(i11, o13) {
    var r10;
    void 0 === o13 && (o13 = {});
    const { x: a10, y: l11, platform: s11, rects: c10, elements: f11, strategy: m12 } = i11, { boundary: u10 = "clippingAncestors", rootBoundary: d12 = "viewport", elementContext: g9 = "floating", altBoundary: p10 = false, padding: h10 = 0 } = h8(o13, i11), y10 = k7(h10), w10 = f11[p10 ? "floating" === g9 ? "reference" : "floating" : g9], x11 = q7(await s11.getClippingRect({ element: null == (r10 = await (null == s11.isElement ? void 0 : s11.isElement(w10))) || r10 ? w10 : w10.contextElement || await (null == s11.getDocumentElement ? void 0 : s11.getDocumentElement(f11.floating)), boundary: u10, rootBoundary: d12, strategy: m12 })), v12 = "floating" === g9 ? { ...c10.floating, x: a10, y: l11 } : c10.reference, b11 = await (null == s11.getOffsetParent ? void 0 : s11.getOffsetParent(f11.floating)), A10 = await (null == s11.isElement ? void 0 : s11.isElement(b11)) && await (null == s11.getScale ? void 0 : s11.getScale(b11)) || { x: 1, y: 1 }, R8 = q7(s11.convertOffsetParentRelativeRectToViewportRelativeRect ? await s11.convertOffsetParentRelativeRectToViewportRelativeRect({ elements: f11, rect: v12, offsetParent: b11, strategy: m12 }) : v12);
    return { top: (x11.top - R8.top + y10.top) / A10.y, bottom: (R8.bottom - x11.bottom + y10.bottom) / A10.y, left: (x11.left - R8.left + y10.left) / A10.x, right: (R8.right - x11.right + y10.right) / A10.x };
  }
  var P8 = function(t17) {
    return void 0 === t17 && (t17 = {}), { name: "flip", options: t17, async fn(n13) {
      var i11, o13;
      const { placement: r10, middlewareData: a10, rects: l11, initialPlacement: s11, platform: g9, elements: p10 } = n13, { mainAxis: h10 = true, crossAxis: y10 = true, fallbackPlacements: w10, fallbackStrategy: x11 = "bestFit", fallbackAxisSideDirection: v12 = "none", flipAlignment: A10 = true, ...R8 } = h8(t17, n13);
      if (null != (i11 = a10.arrow) && i11.alignmentOffset)
        return {};
      const P10 = p8(r10), D7 = p8(s11) === s11, T9 = await (null == g9.isRTL ? void 0 : g9.isRTL(p10.floating)), E10 = w10 || (D7 || !A10 ? [v8(s11)] : y8(s11));
      w10 || "none" === v12 || E10.push(...w8(s11, A10, v12, T9));
      const O9 = [s11, ...E10], L10 = await b9(n13, R8), k10 = [];
      let C9 = (null == (o13 = a10.flip) ? void 0 : o13.overflows) || [];
      if (h10 && k10.push(L10[P10]), y10) {
        const e22 = x8(r10, l11, T9);
        k10.push(L10[e22[0]], L10[e22[1]]);
      }
      if (C9 = [...C9, { placement: r10, overflows: k10 }], !k10.every((e22) => e22 <= 0)) {
        var B8, H8;
        const e22 = ((null == (B8 = a10.flip) ? void 0 : B8.index) || 0) + 1, t18 = O9[e22];
        if (t18)
          return { data: { index: e22, overflows: C9 }, reset: { placement: t18 } };
        let n14 = null == (H8 = C9.filter((e23) => e23.overflows[0] <= 0).sort((e23, t19) => e23.overflows[1] - t19.overflows[1])[0]) ? void 0 : H8.placement;
        if (!n14)
          switch (x11) {
            case "bestFit": {
              var S8;
              const e23 = null == (S8 = C9.map((e24) => [e24.placement, e24.overflows.filter((e25) => e25 > 0).reduce((e25, t19) => e25 + t19, 0)]).sort((e24, t19) => e24[1] - t19[1])[0]) ? void 0 : S8[0];
              e23 && (n14 = e23);
              break;
            }
            case "initialPlacement":
              n14 = s11;
          }
        if (r10 !== n14)
          return { reset: { placement: n14 } };
      }
      return {};
    } };
  };

  // http-url:https://cdn.jsdelivr.net/npm/@floating-ui/utils@0.1.6/+esm
  var t14 = ["top", "right", "bottom", "left"];
  var n10 = ["start", "end"];
  var o10 = t14.reduce((t17, o13) => t17.concat(o13, o13 + "-" + n10[0], o13 + "-" + n10[1]), []);
  var r8 = Math.min;
  var e19 = Math.max;
  var u8 = Math.round;
  var c8 = (t17) => ({ x: t17, y: t17 });

  // http-url:https://cdn.jsdelivr.net/npm/@floating-ui/utils@0.1.6/dom/+esm
  function n11(n13) {
    return o11(n13) ? (n13.nodeName || "").toLowerCase() : "#document";
  }
  function e20(n13) {
    var e22;
    return (null == n13 || null == (e22 = n13.ownerDocument) ? void 0 : e22.defaultView) || window;
  }
  function t15(n13) {
    var e22;
    return null == (e22 = (o11(n13) ? n13.ownerDocument : n13.document) || window.document) ? void 0 : e22.documentElement;
  }
  function o11(n13) {
    return n13 instanceof Node || n13 instanceof e20(n13).Node;
  }
  function r9(n13) {
    return n13 instanceof Element || n13 instanceof e20(n13).Element;
  }
  function c9(n13) {
    return n13 instanceof HTMLElement || n13 instanceof e20(n13).HTMLElement;
  }
  function u9(n13) {
    return "undefined" != typeof ShadowRoot && (n13 instanceof ShadowRoot || n13 instanceof e20(n13).ShadowRoot);
  }
  function i8(n13) {
    const { overflow: e22, overflowX: t17, overflowY: o13, display: r10 } = m10(n13);
    return /auto|scroll|overlay|hidden|clip/.test(e22 + o13 + t17) && !["inline", "contents"].includes(r10);
  }
  function l9(e22) {
    return ["table", "td", "th"].includes(n11(e22));
  }
  function f9(n13) {
    const e22 = a8(), t17 = m10(n13);
    return "none" !== t17.transform || "none" !== t17.perspective || !!t17.containerType && "normal" !== t17.containerType || !e22 && !!t17.backdropFilter && "none" !== t17.backdropFilter || !e22 && !!t17.filter && "none" !== t17.filter || ["transform", "perspective", "filter"].some((n14) => (t17.willChange || "").includes(n14)) || ["paint", "layout", "strict", "content"].some((n14) => (t17.contain || "").includes(n14));
  }
  function s9(n13) {
    let e22 = w9(n13);
    for (; c9(e22) && !d10(e22); ) {
      if (f9(e22))
        return e22;
      e22 = w9(e22);
    }
    return null;
  }
  function a8() {
    return !("undefined" == typeof CSS || !CSS.supports) && CSS.supports("-webkit-backdrop-filter", "none");
  }
  function d10(e22) {
    return ["html", "body", "#document"].includes(n11(e22));
  }
  function m10(n13) {
    return e20(n13).getComputedStyle(n13);
  }
  function p9(n13) {
    return r9(n13) ? { scrollLeft: n13.scrollLeft, scrollTop: n13.scrollTop } : { scrollLeft: n13.pageXOffset, scrollTop: n13.pageYOffset };
  }
  function w9(e22) {
    if ("html" === n11(e22))
      return e22;
    const o13 = e22.assignedSlot || e22.parentNode || u9(e22) && e22.host || t15(e22);
    return u9(o13) ? o13.host : o13;
  }
  function v10(n13) {
    const e22 = w9(n13);
    return d10(e22) ? n13.ownerDocument ? n13.ownerDocument.body : n13.body : c9(e22) && i8(e22) ? e22 : v10(e22);
  }
  function y9(n13, t17, o13) {
    var r10;
    void 0 === t17 && (t17 = []), void 0 === o13 && (o13 = true);
    const c10 = v10(n13), u10 = c10 === (null == (r10 = n13.ownerDocument) ? void 0 : r10.body), l11 = e20(c10);
    return u10 ? t17.concat(l11, l11.visualViewport || [], i8(c10) ? c10 : [], l11.frameElement && o13 ? y9(l11.frameElement) : []) : t17.concat(c10, y9(c10, [], o13));
  }

  // http-url:https://cdn.jsdelivr.net/npm/@floating-ui/dom@1.5.1/+esm
  function L8(t17) {
    const e22 = m10(t17);
    let n13 = parseFloat(e22.width) || 0, o13 = parseFloat(e22.height) || 0;
    const r10 = c9(t17), l11 = r10 ? t17.offsetWidth : n13, c10 = r10 ? t17.offsetHeight : o13, s11 = u8(n13) !== l11 || u8(o13) !== c10;
    return s11 && (n13 = l11, o13 = c10), { width: n13, height: o13, $: s11 };
  }
  function R7(t17) {
    return r9(t17) ? t17 : t17.contextElement;
  }
  function T8(t17) {
    const e22 = R7(t17);
    if (!c9(e22))
      return c8(1);
    const o13 = e22.getBoundingClientRect(), { width: r10, height: l11, $: c10 } = L8(e22);
    let s11 = (c10 ? u8(o13.width) : o13.width) / r10, f11 = (c10 ? u8(o13.height) : o13.height) / l11;
    return s11 && Number.isFinite(s11) || (s11 = 1), f11 && Number.isFinite(f11) || (f11 = 1), { x: s11, y: f11 };
  }
  var E9 = c8(0);
  function F8(t17) {
    const e22 = e20(t17);
    return a8() && e22.visualViewport ? { x: e22.visualViewport.offsetLeft, y: e22.visualViewport.offsetTop } : E9;
  }
  function O8(t17, i11, o13, r10) {
    void 0 === i11 && (i11 = false), void 0 === o13 && (o13 = false);
    const l11 = t17.getBoundingClientRect(), c10 = R7(t17);
    let f11 = c8(1);
    i11 && (r10 ? r9(r10) && (f11 = T8(r10)) : f11 = T8(t17));
    const u10 = function(t18, e22, n13) {
      return void 0 === e22 && (e22 = false), !(!n13 || e22 && n13 !== e20(t18)) && e22;
    }(c10, o13, r10) ? F8(c10) : c8(0);
    let d12 = (l11.left + u10.x) / f11.x, p10 = (l11.top + u10.y) / f11.y, g9 = l11.width / f11.x, m12 = l11.height / f11.y;
    if (c10) {
      const t18 = e20(c10), e22 = r10 && r9(r10) ? e20(r10) : r10;
      let n13 = t18.frameElement;
      for (; n13 && r10 && e22 !== t18; ) {
        const t19 = T8(n13), e23 = n13.getBoundingClientRect(), i12 = m10(n13), o14 = e23.left + (n13.clientLeft + parseFloat(i12.paddingLeft)) * t19.x, r11 = e23.top + (n13.clientTop + parseFloat(i12.paddingTop)) * t19.y;
        d12 *= t19.x, p10 *= t19.y, g9 *= t19.x, m12 *= t19.y, d12 += o14, p10 += r11, n13 = e20(n13).frameElement;
      }
    }
    return q7({ width: g9, height: m12, x: d12, y: p10 });
  }
  function W7(t17) {
    return O8(t15(t17)).left + p9(t17).scrollLeft;
  }
  function H7(t17, i11, r10) {
    let l11;
    if ("viewport" === i11)
      l11 = function(t18, e22) {
        const n13 = e20(t18), i12 = t15(t18), o13 = n13.visualViewport;
        let r11 = i12.clientWidth, l12 = i12.clientHeight, s11 = 0, f11 = 0;
        if (o13) {
          r11 = o13.width, l12 = o13.height;
          const t19 = a8();
          (!t19 || t19 && "fixed" === e22) && (s11 = o13.offsetLeft, f11 = o13.offsetTop);
        }
        return { width: r11, height: l12, x: s11, y: f11 };
      }(t17, r10);
    else if ("document" === i11)
      l11 = function(t18) {
        const e22 = t15(t18), n13 = p9(t18), i12 = t18.ownerDocument.body, r11 = e19(e22.scrollWidth, e22.clientWidth, i12.scrollWidth, i12.clientWidth), l12 = e19(e22.scrollHeight, e22.clientHeight, i12.scrollHeight, i12.clientHeight);
        let s11 = -n13.scrollLeft + W7(t18);
        const f11 = -n13.scrollTop;
        return "rtl" === m10(i12).direction && (s11 += e19(e22.clientWidth, i12.clientWidth) - r11), { width: r11, height: l12, x: s11, y: f11 };
      }(t15(t17));
    else if (r9(i11))
      l11 = function(t18, e22) {
        const i12 = O8(t18, true, "fixed" === e22), o13 = i12.top + t18.clientTop, r11 = i12.left + t18.clientLeft, l12 = c9(t18) ? T8(t18) : c8(1);
        return { width: t18.clientWidth * l12.x, height: t18.clientHeight * l12.y, x: r11 * l12.x, y: o13 * l12.y };
      }(i11, r10);
    else {
      const e22 = F8(t17);
      l11 = { ...i11, x: i11.x - e22.x, y: i11.y - e22.y };
    }
    return q7(l11);
  }
  function z7(t17, e22) {
    const n13 = w9(t17);
    return !(n13 === e22 || !r9(n13) || d10(n13)) && ("fixed" === m10(n13).position || z7(n13, e22));
  }
  function A9(t17, e22, i11) {
    const o13 = c9(e22), r10 = t15(e22), l11 = "fixed" === i11, s11 = O8(t17, true, l11, e22);
    let f11 = { scrollLeft: 0, scrollTop: 0 };
    const h10 = c8(0);
    if (o13 || !o13 && !l11)
      if (("body" !== n11(e22) || i8(r10)) && (f11 = p9(e22)), o13) {
        const t18 = O8(e22, true, l11, e22);
        h10.x = t18.x + e22.clientLeft, h10.y = t18.y + e22.clientTop;
      } else
        r10 && (h10.x = W7(r10));
    return { x: s11.left + f11.scrollLeft - h10.x, y: s11.top + f11.scrollTop - h10.y, width: s11.width, height: s11.height };
  }
  function C8(t17, e22) {
    return c9(t17) && "fixed" !== m10(t17).position ? e22 ? e22(t17) : t17.offsetParent : null;
  }
  function P9(t17, e22) {
    const n13 = e20(t17);
    if (!c9(t17))
      return n13;
    let i11 = C8(t17, e22);
    for (; i11 && l9(i11) && "static" === m10(i11).position; )
      i11 = C8(i11, e22);
    return i11 && ("html" === n11(i11) || "body" === n11(i11) && "static" === m10(i11).position && !f9(i11)) ? n13 : i11 || s9(t17) || n13;
  }
  var B7 = { convertOffsetParentRelativeRectToViewportRelativeRect: function(t17) {
    let { rect: e22, offsetParent: i11, strategy: o13 } = t17;
    const r10 = c9(i11), l11 = t15(i11);
    if (i11 === l11)
      return e22;
    let s11 = { scrollLeft: 0, scrollTop: 0 }, f11 = c8(1);
    const h10 = c8(0);
    if ((r10 || !r10 && "fixed" !== o13) && (("body" !== n11(i11) || i8(l11)) && (s11 = p9(i11)), c9(i11))) {
      const t18 = O8(i11);
      f11 = T8(i11), h10.x = t18.x + i11.clientLeft, h10.y = t18.y + i11.clientTop;
    }
    return { width: e22.width * f11.x, height: e22.height * f11.y, x: e22.x * f11.x - s11.scrollLeft * f11.x + h10.x, y: e22.y * f11.y - s11.scrollTop * f11.y + h10.y };
  }, getDocumentElement: t15, getClippingRect: function(t17) {
    let { element: e22, boundary: n13, rootBoundary: i11, strategy: l11 } = t17;
    const c10 = [..."clippingAncestors" === n13 ? function(t18, e23) {
      const n14 = e23.get(t18);
      if (n14)
        return n14;
      let i12 = y9(t18).filter((t19) => r9(t19) && "body" !== n11(t19)), o13 = null;
      const r10 = "fixed" === m10(t18).position;
      let l12 = r10 ? w9(t18) : t18;
      for (; r9(l12) && !d10(l12); ) {
        const e24 = m10(l12), n15 = f9(l12);
        n15 || "fixed" !== e24.position || (o13 = null), (r10 ? !n15 && !o13 : !n15 && "static" === e24.position && o13 && ["absolute", "fixed"].includes(o13.position) || i8(l12) && !n15 && z7(t18, l12)) ? i12 = i12.filter((t19) => t19 !== l12) : o13 = e24, l12 = w9(l12);
      }
      return e23.set(t18, i12), i12;
    }(e22, this._c) : [].concat(n13), i11], u10 = c10[0], h10 = c10.reduce((t18, n14) => {
      const i12 = H7(e22, n14, l11);
      return t18.top = e19(i12.top, t18.top), t18.right = r8(i12.right, t18.right), t18.bottom = r8(i12.bottom, t18.bottom), t18.left = e19(i12.left, t18.left), t18;
    }, H7(e22, u10, l11));
    return { width: h10.right - h10.left, height: h10.bottom - h10.top, x: h10.left, y: h10.top };
  }, getOffsetParent: P9, getElementRects: async function(t17) {
    let { reference: e22, floating: n13, strategy: i11 } = t17;
    const o13 = this.getOffsetParent || P9, r10 = this.getDimensions;
    return { reference: A9(e22, await o13(n13), i11), floating: { x: 0, y: 0, ...await r10(n13) } };
  }, getClientRects: function(t17) {
    return Array.from(t17.getClientRects());
  }, getDimensions: function(t17) {
    return L8(t17);
  }, getScale: T8, isElement: r9, isRTL: function(t17) {
    return "rtl" === m10(t17).direction;
  } };
  var V7 = (e22, n13, i11) => {
    const o13 = /* @__PURE__ */ new Map(), r10 = { platform: B7, ...i11 }, l11 = { ...r10.platform, _c: o13 };
    return v9(e22, n13, { ...r10, platform: l11 });
  };

  // components/tooltip.js
  var Tooltip = class extends k {
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
      const { x: x11, y: y10 } = this.state.node.cy().container().getBoundingClientRect();
      const tooltip = this.base;
      const theNode = this.state.node;
      const virtualElt = {
        getBoundingClientRect() {
          const bbox = theNode.renderedBoundingBox();
          return {
            x: bbox.x1 + x11,
            y: bbox.y1 + y10,
            top: bbox.y1 + y10,
            left: bbox.x1 + x11,
            bottom: bbox.y2 + y10,
            right: bbox.x2 + x11,
            height: bbox.h,
            width: bbox.w
          };
        }
      };
      V7(virtualElt, tooltip, {
        placement: "right-end",
        middleware: [P8()]
      }).then(
        ({ x: x12, y: y11, placement }) => this.positionAt(x12, y11, placement)
      );
    }
    positionAt(x11, y10, placement) {
      this.setState({
        style: {
          flexDirection: placement.slice(-3) == "end" ? "column-reverse" : "column",
          visibility: "visible",
          left: `${x11}px`,
          top: `${y10}px`,
          zIndex: 5
        }
      });
    }
    getViewData() {
      switch (this.state.mode) {
        case "constraints": {
          return m2`<pre>${this.state.node?.data().constraints?.map?.(
            (c10) => m2`<div>${c10}</div>`
          )}</pre>`;
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
          } else if (this.state.node.data().spinning) {
            return m2`<pre>Spinning: Loop bounds exceeded</pre>`;
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
        case "simprocs": {
          return m2`<pre>${this.state.node?.data().simprocs?.map?.(
            (simproc) => m2`<div>${simproc}</div>`
          )}</pre>`;
        }
        case "assertion": {
          if (this.state.node?.data().assertion_info) {
            return m2`
          <div>${this.state.node?.data().assertion_info}</div>
          <pre>
          Condition: ${this.state.node?.data().failed_cond}<br/>
          Address: ${this.state.node?.data().assertion_addr}
          </pre>
          `;
          } else {
            return null;
          }
        }
        case "postcondition": {
          if (this.state.node?.data().postcondition_info) {
            return m2`
          <div>${this.state.node?.data().postcondition_info}</div>
          <pre>
          Condition: ${this.state.node?.data().failed_cond}<br/>
          </pre>
          `;
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
        ${this.state.node?.data().constraints && m2`
          <button
            data-highlighted=${state.mode == "constraints"} 
            onClick=${() => this.setView("constraints")}>
            Constraints
          </button>`}
        ${this.state.node?.data().vex && m2`
          <button 
            data-highlighted=${state.mode == "vex"} 
            onClick=${() => this.setView("vex")}>
            Vex IR
          </button>`}
        ${(this.state.node?.data().error || this.state.node?.data().spinning) && m2`
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
        ${this.state.node?.data().simprocs?.length > 0 && m2`
          <button 
            data-highlighted=${state.mode == "simprocs"} 
            onClick=${() => this.setView("simprocs")}>
            SimProcedures
          </button>`}
        ${this.state.node?.data().assertion_info && m2`
          <button 
            data-highlighted=${state.mode == "assertion"} 
            onClick=${() => this.setView("assertion")}>
            Assertion
          </button>`}
        ${this.state.node?.data().postcondition_info && m2`
          <button 
            data-highlighted=${state.mode == "postcondition"} 
            onClick=${() => this.setView("postcondition")}>
            Postcondition
          </button>`}
      </div>
      <div id="tooltip-data">${this.getViewData()}</div>
    </div>`;
    }
  };

  // components/concretions.js
  var Concretions = class extends k {
    constructor() {
      super();
      this.state = {
        view: "shared"
      };
    }
    render(props, state) {
      const rightId = props.rightFocus.bot.id();
      const leftId = props.leftFocus.bot.id();
      const examples = [];
      const sharedConcretions = props.leftFocus.bot.data().compatibilities[rightId].conc_args;
      const leftOnlyConcretions = Object.entries(props.leftFocus.bot.data().compatibilities).flatMap(
        ([key, compat]) => key == rightId ? [] : compat.conc_args
      );
      const rightOnlyConcretions = Object.entries(props.rightFocus.bot.data().compatibilities).flatMap(
        ([key, compat]) => key == leftId ? [] : compat.conc_args
      );
      const concretions = state.view == "shared" ? sharedConcretions : state.view == "left" ? leftOnlyConcretions : state.view == "right" ? rightOnlyConcretions : null;
      for (const concretion of concretions) {
        examples.push(m2`
        <pre class="concrete-example">${JSON.stringify(concretion, void 0, 2)}</pre>
      `);
      }
      const sharedMsg = sharedConcretions.length == 0 ? "No concretions available" : m2`Viewing ${sharedConcretions.length} concrete input examples shared by both branches`;
      const leftMsg = leftOnlyConcretions.length == 0 ? rightOnlyConcretions.length == 0 ? "There are no inputs that go down the left but not the right branch. The two branches correspond to exactly the same inputs." : "There are no inputs that go down the left but not the right branch. The left branch refines the right." : m2`Viewing ${leftOnlyConcretions.length} concrete input examples that go down the left but not the right branch`;
      const rightMsg = rightOnlyConcretions.length == 0 ? leftOnlyConcretions.length == 0 ? "There are no inputs that go down the right but not the left branch. The two branches correspond to exactly the same inputs." : "There are no inputs that go down the right but not the left branch. The right branch refines the left." : m2`Viewing ${rightOnlyConcretions.length} concrete input examples that go down the right but not the left branch`;
      return m2`
    <div class="subordinate-buttons">
      <button
        data-selected=${state.view == "shared"}
        onClick=${() => this.setState({ view: "shared" })}
      >Shared</button>
      <button
        data-selected=${state.view == "left"}
        onClick=${() => this.setState({ view: "left" })}
      >Left Branch Only</button>
      <button
        data-selected=${state.view == "right"}
        onClick=${() => this.setState({ view: "right" })}
      >Right Branch Only</button>
    </div>
    <div id="concretion-header">
      ${state.view == "shared" ? sharedMsg : state.view == "left" ? leftMsg : state.view == "right" ? rightMsg : null}
    </div>
    <div id="concretion-data">
      ${examples}
    </div>`;
    }
  };

  // util/segmentation.js
  function getNodesFromEnds(top, bottom) {
    const interval = [bottom];
    while (interval[interval.length - 1].id() !== top.id()) {
      interval.push(interval[interval.length - 1].incomers("node")[0]);
    }
    return interval;
  }
  function getEdgesFromEnds(top, bottom) {
    const nodes = getNodesFromEnds(top, bottom);
    nodes.pop();
    return nodes.map((node) => node.incomers("edge")[0]);
  }
  var Segment = class _Segment {
    constructor(top, bot) {
      this.cy = Pl({
        elements: bot.predecessors().intersection(top.successors()).union(top).union(bot).jsons()
      });
      this.top = this.cy.nodes().roots()[0];
      this.bot = this.cy.nodes().leaves()[0];
      this.cy = () => bot.cy();
    }
    static fromRange(range) {
      const bot = range.filter((ele) => ele.outgoers("node").intersection(range).length == 0)[0];
      const top = range.filter((ele) => ele.incomers("node").intersection(range).length == 0)[0];
      return new _Segment(top, bot);
    }
  };

  // components/hunk.js
  function hunkFormat(hunk, className) {
    const terminator = hunk.slice(-1);
    if (terminator === ">" || terminator == ",") {
      const newHunk = hunk.slice(0, hunk.length - 1);
      return m2`<span class=${className}>${newHunk}</span>${terminator} `;
    } else {
      return m2`<span class=${className}>${hunk}</span> `;
    }
  }
  function Hunk({ dim, highlight, hunkCtx, curLeft, curRight, leftContent, leftClass, rightContent, rightClass }) {
    const hunk = m2`<div
        onMouseEnter=${highlight} 
        onMouseLeave=${dim}
        >
        <div
          title=${hunkCtx?.leftMsgs[curLeft]}
          class=${leftClass}
        >${leftContent}</div>
        <div
          title=${hunkCtx?.rightMsgs[curRight]}
          class=${rightClass}
        >${rightContent}</div>
      </div>`;
    hunk.contentListing = { left: leftContent, right: rightContent };
    return hunk;
  }

  // http-url:https://cdn.jsdelivr.net/npm/diff@5.1.0/+esm
  function e21() {
  }
  function n12(e22, n13, t17, r10, i11) {
    for (var o13 = 0, l11 = n13.length, s11 = 0, a10 = 0; o13 < l11; o13++) {
      var u10 = n13[o13];
      if (u10.removed) {
        if (u10.value = e22.join(r10.slice(a10, a10 + u10.count)), a10 += u10.count, o13 && n13[o13 - 1].added) {
          var f11 = n13[o13 - 1];
          n13[o13 - 1] = n13[o13], n13[o13] = f11;
        }
      } else {
        if (!u10.added && i11) {
          var d12 = t17.slice(s11, s11 + u10.count);
          d12 = d12.map(function(e23, n14) {
            var t18 = r10[a10 + n14];
            return t18.length > e23.length ? t18 : e23;
          }), u10.value = e22.join(d12);
        } else
          u10.value = e22.join(t17.slice(s11, s11 + u10.count));
        s11 += u10.count, u10.added || (a10 += u10.count);
      }
    }
    var c10 = n13[l11 - 1];
    return l11 > 1 && "string" == typeof c10.value && (c10.added || c10.removed) && e22.equals("", c10.value) && (n13[l11 - 2].value += c10.value, n13.pop()), n13;
  }
  e21.prototype = { diff: function(e22, t17) {
    var r10 = arguments.length > 2 && void 0 !== arguments[2] ? arguments[2] : {}, i11 = r10.callback;
    "function" == typeof r10 && (i11 = r10, r10 = {}), this.options = r10;
    var o13 = this;
    function l11(e23) {
      return i11 ? (setTimeout(function() {
        i11(void 0, e23);
      }, 0), true) : e23;
    }
    e22 = this.castInput(e22), t17 = this.castInput(t17), e22 = this.removeEmpty(this.tokenize(e22));
    var s11 = (t17 = this.removeEmpty(this.tokenize(t17))).length, a10 = e22.length, u10 = 1, f11 = s11 + a10;
    r10.maxEditLength && (f11 = Math.min(f11, r10.maxEditLength));
    var d12 = [{ newPos: -1, components: [] }], c10 = this.extractCommon(d12[0], t17, e22, 0);
    if (d12[0].newPos + 1 >= s11 && c10 + 1 >= a10)
      return l11([{ value: this.join(t17), count: t17.length }]);
    function h10() {
      for (var r11 = -1 * u10; r11 <= u10; r11 += 2) {
        var i12 = void 0, f12 = d12[r11 - 1], c11 = d12[r11 + 1], h11 = (c11 ? c11.newPos : 0) - r11;
        f12 && (d12[r11 - 1] = void 0);
        var p11 = f12 && f12.newPos + 1 < s11, v12 = c11 && 0 <= h11 && h11 < a10;
        if (p11 || v12) {
          if (!p11 || v12 && f12.newPos < c11.newPos ? (i12 = { newPos: (g9 = c11).newPos, components: g9.components.slice(0) }, o13.pushComponent(i12.components, void 0, true)) : ((i12 = f12).newPos++, o13.pushComponent(i12.components, true, void 0)), h11 = o13.extractCommon(i12, t17, e22, r11), i12.newPos + 1 >= s11 && h11 + 1 >= a10)
            return l11(n12(o13, i12.components, t17, e22, o13.useLongestToken));
          d12[r11] = i12;
        } else
          d12[r11] = void 0;
      }
      var g9;
      u10++;
    }
    if (i11)
      !function e23() {
        setTimeout(function() {
          if (u10 > f11)
            return i11();
          h10() || e23();
        }, 0);
      }();
    else
      for (; u10 <= f11; ) {
        var p10 = h10();
        if (p10)
          return p10;
      }
  }, pushComponent: function(e22, n13, t17) {
    var r10 = e22[e22.length - 1];
    r10 && r10.added === n13 && r10.removed === t17 ? e22[e22.length - 1] = { count: r10.count + 1, added: n13, removed: t17 } : e22.push({ count: 1, added: n13, removed: t17 });
  }, extractCommon: function(e22, n13, t17, r10) {
    for (var i11 = n13.length, o13 = t17.length, l11 = e22.newPos, s11 = l11 - r10, a10 = 0; l11 + 1 < i11 && s11 + 1 < o13 && this.equals(n13[l11 + 1], t17[s11 + 1]); )
      l11++, s11++, a10++;
    return a10 && e22.components.push({ count: a10 }), e22.newPos = l11, s11;
  }, equals: function(e22, n13) {
    return this.options.comparator ? this.options.comparator(e22, n13) : e22 === n13 || this.options.ignoreCase && e22.toLowerCase() === n13.toLowerCase();
  }, removeEmpty: function(e22) {
    for (var n13 = [], t17 = 0; t17 < e22.length; t17++)
      e22[t17] && n13.push(e22[t17]);
    return n13;
  }, castInput: function(e22) {
    return e22;
  }, tokenize: function(e22) {
    return e22.split("");
  }, join: function(e22) {
    return e22.join("");
  } };
  var t16 = new e21();
  function i10(e22, n13) {
    if ("function" == typeof e22)
      n13.callback = e22;
    else if (e22)
      for (var t17 in e22)
        e22.hasOwnProperty(t17) && (n13[t17] = e22[t17]);
    return n13;
  }
  var o12 = /^[A-Za-z\xC0-\u02C6\u02C8-\u02D7\u02DE-\u02FF\u1E00-\u1EFF]+$/;
  var l10 = /\S/;
  var s10 = new e21();
  function a9(e22, n13, t17) {
    return t17 = i10(t17, { ignoreWhitespace: true }), s10.diff(e22, n13, t17);
  }
  s10.equals = function(e22, n13) {
    return this.options.ignoreCase && (e22 = e22.toLowerCase(), n13 = n13.toLowerCase()), e22 === n13 || this.options.ignoreWhitespace && !l10.test(e22) && !l10.test(n13);
  }, s10.tokenize = function(e22) {
    for (var n13 = e22.split(/([^\S\r\n]+|[()[\]{}'"\r\n]|\b)/), t17 = 0; t17 < n13.length - 1; t17++)
      !n13[t17 + 1] && n13[t17 + 2] && o12.test(n13[t17]) && o12.test(n13[t17 + 2]) && (n13[t17] += n13[t17 + 2], n13.splice(t17 + 1, 2), t17--);
    return n13;
  };
  var f10 = new e21();
  function d11(e22, n13, t17) {
    return f10.diff(e22, n13, t17);
  }
  f10.tokenize = function(e22) {
    var n13 = [], t17 = e22.split(/(\n|\r\n)/);
    t17[t17.length - 1] || t17.pop();
    for (var r10 = 0; r10 < t17.length; r10++) {
      var i11 = t17[r10];
      r10 % 2 && !this.options.newlineIsToken ? n13[n13.length - 1] += i11 : (this.options.ignoreWhitespace && (i11 = i11.trim()), n13.push(i11));
    }
    return n13;
  };
  var h9 = new e21();
  h9.tokenize = function(e22) {
    return e22.split(/(\S.+?[.!?])(?=\s+|$)/);
  };
  var v11 = new e21();
  function m11(e22) {
    return m11 = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(e23) {
      return typeof e23;
    } : function(e23) {
      return e23 && "function" == typeof Symbol && e23.constructor === Symbol && e23 !== Symbol.prototype ? "symbol" : typeof e23;
    }, m11(e22);
  }
  v11.tokenize = function(e22) {
    return e22.split(/([{}:;,]|\s+)/);
  };
  var x10 = Object.prototype.toString;
  var L9 = new e21();
  function k9(e22, n13, t17, r10, i11) {
    var o13, l11;
    for (n13 = n13 || [], t17 = t17 || [], r10 && (e22 = r10(i11, e22)), o13 = 0; o13 < n13.length; o13 += 1)
      if (n13[o13] === e22)
        return t17[o13];
    if ("[object Array]" === x10.call(e22)) {
      for (n13.push(e22), l11 = new Array(e22.length), t17.push(l11), o13 = 0; o13 < e22.length; o13 += 1)
        l11[o13] = k9(e22[o13], n13, t17, r10, i11);
      return n13.pop(), t17.pop(), l11;
    }
    if (e22 && e22.toJSON && (e22 = e22.toJSON()), "object" === m11(e22) && null !== e22) {
      n13.push(e22), l11 = {}, t17.push(l11);
      var s11, a10 = [];
      for (s11 in e22)
        e22.hasOwnProperty(s11) && a10.push(s11);
      for (a10.sort(), o13 = 0; o13 < a10.length; o13 += 1)
        l11[s11 = a10[o13]] = k9(e22[s11], n13, t17, r10, s11);
      n13.pop(), t17.pop();
    } else
      l11 = e22;
    return l11;
  }
  L9.useLongestToken = true, L9.tokenize = f10.tokenize, L9.castInput = function(e22) {
    var n13 = this.options, t17 = n13.undefinedReplacement, r10 = n13.stringifyReplacer, i11 = void 0 === r10 ? function(e23, n14) {
      return void 0 === n14 ? t17 : n14;
    } : r10;
    return "string" == typeof e22 ? e22 : JSON.stringify(k9(e22, null, null, i11), i11, "  ");
  }, L9.equals = function(n13, t17) {
    return e21.prototype.equals.call(L9, n13.replace(/,([\r\n])/g, "$1"), t17.replace(/,([\r\n])/g, "$1"));
  };
  var b10 = new e21();
  b10.tokenize = function(e22) {
    return e22.slice();
  }, b10.join = b10.removeEmpty = function(e22) {
    return e22;
  };

  // components/lineDiffView.js
  var LineDiffView = class extends k {
    getContents() {
      if (!this.props.leftLines && !this.props.rightLines)
        return null;
      if (!this.props.rightLines) {
        const {
          lines: leftLines,
          ids: leftIds,
          msgs: leftMsgs
        } = this.props.leftLines;
        const hunkCtx = { leftIds, rightIds: [""], leftMsgs, rightMsgs: [""] };
        return leftLines.map((line, idx) => Hunk({
          hunkCtx,
          curLeft: idx,
          curRight: 0,
          leftContent: this.props.format?.(line) || line,
          rightContent: " "
        }));
      }
      if (!this.props.leftLines) {
        const {
          lines: rightLines,
          ids: rightIds,
          msgs: rightMsgs
        } = this.props.rightLines;
        const hunkCtx = { rightIds, leftIds: [""], rightMsgs, leftMsgs: [""] };
        return rightLines.map((line, idx) => Hunk({
          hunkCtx,
          curLeft: 0,
          curRight: idx,
          leftContent: " ",
          rightContent: this.props.format?.(line) || line
        }));
      }
      return this.diffLines();
    }
    diffLines() {
      if (this.prevLeftLines == this.props.leftLines && this.prevRightLines == this.props.rightLines) {
        return this.prevDiff;
      }
      this.prevLeftFocus = this.props.leftFocus;
      this.prevRightFocus = this.props.rightFocus;
      const {
        contents: leftContents,
        lines: leftLines,
        ids: leftIds,
        msgs: leftMsgs
      } = this.props.leftLines;
      const {
        contents: rightContents,
        lines: rightLines,
        ids: rightIds,
        msgs: rightMsgs
      } = this.props.rightLines;
      const hunkCtx = { leftIds, leftMsgs, rightIds, rightMsgs };
      const diffs = d11(leftContents, rightContents, {
        comparator: this.props.comparator
      });
      let rendered = [];
      let curLeft = 0;
      let curRight = 0;
      let mkHunk = ({ curLeft: curLeft2, curRight: curRight2, leftContent, rightContent, leftClass, rightClass }) => Hunk({
        highlight: this.props.highlight ? () => this.props.highlight(leftIds[curLeft2], rightIds[curRight2]) : () => {
        },
        dim: this.props.dim ? () => this.props.dim() : () => {
        },
        hunkCtx,
        curLeft: curLeft2,
        curRight: curRight2,
        leftContent,
        rightContent,
        leftClass,
        rightClass
      });
      for (const diff of diffs) {
        if (diff?.added) {
          for (const line of diff.value.split("\n")) {
            if (line == "")
              continue;
            const hunk = mkHunk({
              curLeft,
              curRight,
              leftContent: " ",
              rightContent: this.props.format?.(line) || line,
              rightClass: "hunkAdded"
            });
            curRight++;
            rendered.push(hunk);
          }
        } else if (diff?.removed) {
          for (const line of diff.value.split("\n")) {
            if (line == "")
              continue;
            const hunk = mkHunk({
              curLeft,
              curRight,
              leftContent: this.props.format?.(line) || line,
              rightContent: " ",
              leftClass: "hunkRemoved"
            });
            curLeft++;
            rendered.push(hunk);
          }
        } else {
          for (let i11 = 0; i11 < diff.count; i11++) {
            let rightContent = this.props.format?.(rightLines[curRight]) || rightLines[curRight];
            let leftContent = this.props.format?.(leftLines[curLeft]) || leftLines[curLeft];
            [leftContent, rightContent] = this.props.diffWords?.(leftContent, rightContent) || [leftContent, rightContent];
            const hunk = mkHunk({
              curLeft,
              curRight,
              leftContent,
              rightContent
            });
            curRight++;
            curLeft++;
            rendered.push(hunk);
          }
        }
      }
      this.prevDiff = rendered;
      return rendered;
    }
    render(props) {
      const hunks = this.getContents().filter(({ contentListing }) => {
        if (!props.filterExpr)
          return true;
        let lineFilter;
        try {
          lineFilter = new RegExp(props.filterExpr);
        } catch (e22) {
          lineFilter = /^/;
        }
        return lineFilter.test(contentListing.left) || lineFilter.test(contentListing.right);
      });
      return m2`<pre id="line-diff-data-view">${hunks}</pre>`;
    }
  };

  // components/searchInput.js
  function SearchInput({ value, onInput }) {
    return m2`<div class="search-input">
      <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-search"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
      <input value="${value}" onInput=${onInput}></input>
      </div>`;
  }

  // components/actionDifference.js
  var ActionDifference = class extends k {
    getActions(focus) {
      const segment = getEdgesFromEnds(focus.top, focus.bot).reverse();
      let contents = "";
      let msg = "";
      const lines = [];
      const ids = [];
      const msgs = [];
      for (const edge of segment) {
        const id = edge.id();
        for (const line of edge.data("actions")) {
          contents += line + "\n";
          lines.push(line);
          msgs.push(msg);
          ids.push(id);
        }
      }
      if (focus.bot.data("actions")) {
        for (const line of focus.bot.data("actions")) {
          contents += line + "\n";
          lines.push(line);
          msgs.push(msg);
          ids.push("bottomNode");
        }
      }
      return { contents, lines, ids, msgs };
    }
    onInput(e22) {
      this.setState({ filterExpr: e22.target.value });
    }
    diffWords(leftLine, rightLine) {
      const lwords = leftLine.split(/\s+/);
      const rwords = rightLine.split(/\s+/);
      const laddr = lwords.shift();
      const raddr = rwords.shift();
      const comparison = lwords.map((lw, idx) => rwords[idx] === lw);
      leftLine = lwords.map((w10, idx) => comparison[idx] ? `${w10} ` : hunkFormat(w10, "hunkRemoved"));
      rightLine = rwords.map((w10, idx) => comparison[idx] ? `${w10} ` : hunkFormat(w10, "hunkAdded"));
      leftLine.unshift(`${laddr} `);
      rightLine.unshift(`${raddr} `);
      return [leftLine, rightLine];
    }
    highlightNodes(idLeft, idRight) {
      const cyLeft = this.props.leftFocus.cy();
      const cyRight = this.props.rightFocus.cy();
      if (idLeft == "bottomNode") {
        const botId = this.props.leftFocus.bot.id();
        cyLeft.highlight(cyLeft.nodes(`#${botId}, [mergedIds*='#${botId}#']`));
      } else {
        const leftEdges = cyLeft.edges(`#${idLeft}, [mergedIds*='#${idLeft}#']`);
        cyLeft.highlight(leftEdges.sources());
      }
      if (idRight == "bottomNode") {
        const botId = this.props.rightFocus.bot.id();
        cyRight.highlight(cyRight.nodes(`#${botId}, [mergedIds*='#${botId}#']`));
      } else {
        const rightEdges = cyRight.edges(`#${idRight}, [mergedIds*='#${idRight}#']`);
        cyRight.highlight(rightEdges.sources());
      }
    }
    dimAll() {
      this.props.leftFocus.cy().dim();
      this.props.rightFocus.cy().dim();
    }
    compare(l11, r10) {
      const [, , laction, ...lterms] = l11.split(/\s+/);
      const [, , raction, ...rterms] = r10.split(/\s+/);
      if (laction === raction) {
        switch (laction) {
          case "reg/write:":
            return lterms[0] == rterms[0] && lterms.length === rterms.length;
          case "reg/read:":
            return lterms[0] == rterms[0] && lterms.length === rterms.length;
          default:
            return lterms.length === rterms.length;
        }
      }
      return false;
    }
    format(s11) {
      let [, ...results] = s11.slice(1, -1).split(/\s+/);
      results = results.map((s12) => {
        switch (s12) {
          case "---->>":
            return "\u2192";
          case "<<----":
            return "\u2190";
          default:
            return s12;
        }
      });
      return results.join(" ");
    }
    render(props, state) {
      return m2`<div id="action-diff">
      <${SearchInput} onInput=${(e22) => this.onInput(e22)} value=${this.filterExpr}/>
      <${LineDiffView} 
      filterExpr=${state.filterExpr}
      leftLines=${props.leftFocus ? this.getActions(props.leftFocus) : null}
      rightLines=${props.rightFocus ? this.getActions(props.rightFocus) : null}
      comparator=${(l11, r10) => this.compare(l11, r10)}
      diffWords=${(l11, r10) => this.diffWords(l11, r10)}
      highlight=${(idLeft, idRight) => this.highlightNodes(idLeft, idRight)}
      format=${(s11) => this.format(s11)}
      dim=${() => this.dimAll()}
      />
      </div>
      `;
    }
  };

  // components/assemblyDifference.js
  var AssemblyDifference = class extends k {
    getAssembly(focus) {
      const segment = getNodesFromEnds(focus.top, focus.bot).reverse();
      let contents = "";
      let msg = "";
      const lines = [];
      const ids = [];
      const msgs = [];
      const debug = focus.cy().debugData;
      for (const node of segment) {
        const id = node.id();
        for (const line of node.data().contents.split("\n")) {
          if (debug) {
            const addr = parseInt(line.match(/^[0-9a-f]*/), 16);
            if (debug[addr])
              msg = "";
            for (const loc of debug[addr] || [])
              msg += loc + "\n";
          }
          contents += line + "\n";
          lines.push(line);
          msgs.push(msg);
          ids.push(id);
        }
      }
      return { contents, lines, ids, msgs };
    }
    onInput(e22) {
      this.setState({ filterExpr: e22.target.value });
    }
    highlightNodes(idLeft, idRight) {
      const cyLeft = this.props.leftFocus.cy();
      const cyRight = this.props.rightFocus.cy();
      cyLeft.highlight(cyLeft.nodes(`#${idLeft}, [mergedIds*='#${idLeft}#']`));
      cyRight.highlight(cyRight.nodes(`#${idRight}, [mergedIds*='#${idRight}#']`));
    }
    dimAll() {
      this.props.leftFocus.cy().dim();
      this.props.rightFocus.cy().dim();
    }
    compare(l11, r10) {
      const [, lmnemonic, ...loperands] = l11.split(/\s+/);
      const [, rmnemonic, ...roperands] = r10.split(/\s+/);
      return lmnemonic == rmnemonic && loperands.length == roperands.length;
    }
    diffWords(leftLine, rightLine) {
      const lwords = leftLine.split(/\s+/);
      const rwords = rightLine.split(/\s+/);
      const laddr = lwords.shift();
      const raddr = rwords.shift();
      const comparison = lwords.map((lw, idx) => rwords[idx] === lw);
      leftLine = lwords.map((w10, idx) => comparison[idx] ? `${w10} ` : hunkFormat(w10, "hunkRemoved"));
      rightLine = rwords.map((w10, idx) => comparison[idx] ? `${w10} ` : hunkFormat(w10, "hunkAdded"));
      leftLine.unshift(`${laddr} `);
      rightLine.unshift(`${raddr} `);
      return [leftLine, rightLine];
    }
    render(props, state) {
      return m2`<div id="assembly-diff">
      <${SearchInput} value=${state.filterExpr} onInput=${(e22) => this.onInput(e22)}/>
      <${LineDiffView} 
      filterExpr=${state.filterExpr}
      leftLines=${props.leftFocus ? this.getAssembly(props.leftFocus) : null}
      rightLines=${props.rightFocus ? this.getAssembly(props.rightFocus) : null}
      comparator=${(l11, r10) => this.compare(l11, r10)}
      diffWords=${(l11, r10) => this.diffWords(l11, r10)}
      highlight=${(idLeft, idRight) => this.highlightNodes(idLeft, idRight)}
      dim=${() => this.dimAll()}
    />
    </div>`;
    }
  };

  // components/concretionSelector.js
  var ConcretionSelector = class extends k {
    render(props) {
      if (props.concretionCount === 0)
        return null;
      const buttons = [
        m2`<button 
      data-selected=${props.view == "symbolic"} 
      onClick=${() => props.setView("symbolic")}
      >Symbolic</button>`
      ];
      for (let i11 = 0; i11 < props.concretionCount; i11++) {
        buttons.push(
          m2`<button 
        data-selected=${props.view == i11} 
        onClick=${() => props.setView(i11)}
        >Example ${i11 + 1}</button>`
        );
      }
      return m2`<div class="subordinate-buttons">${buttons}</div>`;
    }
  };

  // components/registerDifference.js
  var RegisterDifference = class extends k {
    constructor() {
      super();
      this.state = { view: "symbolic" };
    }
    render(props, state) {
      const rightId = props.rightFocus.bot.id();
      const registers = [];
      const conc_regdiffs = props.leftFocus.bot.data().compatibilities[rightId].conc_regdiff ?? [];
      const rdiffs = state.view === "symbolic" ? props.leftFocus.bot.data().compatibilities[rightId].regdiff : conc_regdiffs[state.view];
      for (const reg in rdiffs) {
        registers.push(m2`
        <span class="grid-diff-left">${rdiffs[reg][0]}</span>
        <span class="grid-diff-label">${reg}</span>
        <span class="grid-diff-right">${rdiffs[reg][1]}</span>`);
      }
      return m2`<div>
      <${ConcretionSelector} 
        view=${state.view} 
        setView=${(view) => this.setState({ view })} 
        concretionCount=${conc_regdiffs.length}/>
      <div id="grid-diff-data"> ${registers.length > 0 ? registers : m2`<span class="no-difference">no register differences detected ✓</span>`}</div></div>`;
    }
  };

  // components/memoryDifference.js
  var MemoryDifference = class extends k {
    constructor() {
      super();
      this.state = { view: "symbolic" };
    }
    render(props, state) {
      const rightId = props.rightFocus.bot.id();
      const addresses = [];
      const conc_adiffs = props.leftFocus.bot.data().compatibilities[rightId].conc_memdiff ?? [];
      const adiffs = state.view === "symbolic" ? props.leftFocus.bot.data().compatibilities[rightId].memdiff : conc_adiffs[state.view];
      for (const addr in adiffs) {
        const addrparts = addr.split("\n").map((part) => [part, m2`<br/>`]).flat();
        addresses.push(m2`
        <span class="grid-diff-left">${adiffs[addr][0]}</span>
        <span class="grid-diff-label">${addrparts}</span>
        <span class="grid-diff-right">${adiffs[addr][1]}</span>`);
      }
      return m2`<div>
      <${ConcretionSelector} 
        view=${state.view} 
        setView=${(view) => this.setState({ view })} 
        concretionCount=${conc_adiffs.length}/>
      <div id="grid-diff-data"> ${addresses.length > 0 ? addresses : m2`<span class="no-difference">no memory differences detected ✓</span>`}</div></div>`;
    }
  };

  // components/sideEffectDifference.js
  var SideEffectDifference = class extends k {
    constructor() {
      super();
      this.state = { view: 0 };
    }
    diffableSideEffects(effects, presence) {
      let contents = "";
      let msg = "";
      let effectIdx = 0;
      const lines = [];
      const ids = [];
      const msgs = [];
      for (const isPresent of presence) {
        if (isPresent) {
          contents += effects[effectIdx].body + "\n";
          lines.push(effects[effectIdx].body);
          ids.push(effects[effectIdx].id);
          effectIdx++;
        } else {
          contents += "\n";
          lines.push("");
          ids.push(null);
        }
        msgs.push(msg);
      }
      return { contents, lines, ids, msgs };
    }
    handleSymbolicDiff(symbolicDiff) {
      const rslt = {};
      for (const channel in symbolicDiff) {
        const lines = {};
        lines.left = symbolicDiff[channel].map(([x11]) => ({ body: x11 }));
        lines.right = symbolicDiff[channel].map(([, x11]) => ({ body: x11 }));
        rslt[channel] = lines;
      }
      return rslt;
    }
    highlightNodes(idLeft, idRight) {
      const cyLeft = this.props.leftFocus.cy();
      const cyRight = this.props.rightFocus.cy();
      cyLeft.highlight(cyLeft.nodes(`#${idLeft}, [mergedIds*='#${idLeft}#']`));
      cyRight.highlight(cyRight.nodes(`#${idRight}, [mergedIds*='#${idRight}#']`));
    }
    dimAll() {
      this.props.leftFocus.cy().dim();
      this.props.rightFocus.cy().dim();
    }
    diffWords(leftLine, rightLine) {
      const diffs = a9(leftLine, rightLine);
      const newLeft = [];
      const newRight = [];
      for (const diff of diffs) {
        if (diff?.added) {
          newRight.push(m2`<span class="hunkAdded">${diff.value}</span>`);
        } else if (diff?.removed) {
          newLeft.push(m2`<span class="hunkRemoved">${diff.value}</span>`);
        } else {
          newRight.push(m2`<span>${diff.value}</span>`);
          newLeft.push(m2`<span>${diff.value}</span>`);
        }
      }
      return [newLeft, newRight];
    }
    render(props, state) {
      const rightId = props.rightFocus.bot.id();
      const concretions = props.leftFocus.bot.data().compatibilities[rightId].conc_sediff ?? [];
      const symbolicDiff = props.leftFocus.bot.data().compatibilities[rightId].sediff ?? {};
      const chandivs = [];
      const replacer = (_7, s11) => s11 == "leafNeq" ? "These constraints are not equivalent" : s11 == "fieldEq" ? "The remaining constrants shown here are equivalent" : s11;
      if (state.view == "symbolic") {
        for (const channel in symbolicDiff) {
          const chandiv = m2`<div class="side-effect-channel">
          <h3>${channel}</h3>
          ${symbolicDiff[channel].map(([, , x11]) => m2`<pre>${JSON.stringify(x11, replacer, 2)}</pre>`)}
        </div>`;
          chandivs.push(chandiv);
        }
      } else {
        const sediffs = concretions[state.view];
        for (const channel in sediffs) {
          if (!(channel in symbolicDiff))
            continue;
          const chandiv = m2`<div class="side-effect-channel">
          <h3>${channel}</h3>
          <${LineDiffView} 
            leftLines=${this.diffableSideEffects(
            sediffs[channel].left,
            symbolicDiff[channel].map(([x11]) => x11)
          )}
            rightLines=${this.diffableSideEffects(
            sediffs[channel].right,
            symbolicDiff[channel].map(([, y10]) => y10)
          )}
            diffWords=${(l11, r10) => this.diffWords(l11, r10)}
            comparator=${() => true}
            highlight=${(idLeft, idRight) => this.highlightNodes(idLeft, idRight)}
            dim=${() => this.dimAll()}
          />
        </div>`;
          chandivs.push(chandiv);
        }
      }
      return m2`<div>
      <${ConcretionSelector} 
        view=${state.view} 
        setView=${(view) => this.setState({ view })} 
        concretionCount=${concretions.length}/>
      ${chandivs}
      </div>`;
    }
  };

  // components/diffPanel.js
  var DiffPanel = class extends k {
    constructor() {
      super();
      this.state = {
        mode: null
      };
      this.diffPanel = m();
      this.dragHandle = m();
    }
    toggleMode(mode) {
      if (this.state.mode == mode) {
        this.setState({ mode: null });
      } else {
        this.setState({ mode });
      }
    }
    startResize(e22) {
      this.diffPanel.current.onpointermove = (e23) => {
        this.diffPanel.current.style.maxHeight = `${Math.max(50, window.innerHeight - e23.clientY)}px`;
      };
      this.dragHandle.current.setPointerCapture(e22.pointerId);
      this.dragHandle.current.classList.add("grabbed");
      this.diffPanel.current.classList.add("resizing");
    }
    stopResize(e22) {
      this.diffPanel.current.onpointermove = null;
      this.dragHandle.current.releasePointerCapture(e22.pointerId);
      this.dragHandle.current.classList.remove("grabbed");
      this.diffPanel.current.classList.remove("resizing");
    }
    render(props, state) {
      const assemblyAvailable = props.leftFocus || props.rightFocus;
      const registersAvailable = props.leftFocus && props.rightFocus && props.leftFocus.bot.data().compatibilities?.[props.rightFocus.bot.id()]?.regdiff;
      const memoryAvailable = props.leftFocus && props.rightFocus && props.leftFocus.bot.data().compatibilities?.[props.rightFocus.bot.id()]?.memdiff;
      const concretionAvailable = props.leftFocus && props.rightFocus && props.leftFocus.bot.data().compatibilities?.[props.rightFocus.bot.id()]?.conc_args;
      const actionsAvailable = props.rightFocus?.top.outgoers("edge")[0]?.data("actions")?.length > 0 || props.leftFocus?.top.outgoers("edge")[0]?.data("actions")?.length > 0;
      const sideEffectsAvailable = props.leftFocus && props.rightFocus && props.leftFocus.bot.data().compatibilities?.[props.rightFocus.bot.id()]?.conc_sediff;
      return m2`<div id="diff-panel" onMouseEnter=${props.onMouseEnter} ref=${this.diffPanel}>
      <div id="diff-drag-handle"
        onPointerDown=${(e22) => this.startResize(e22)} 
        onPointerUp=${(e22) => this.stopResize(e22)} 
        ref=${this.dragHandle}
      />
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
        <button disabled=${!actionsAvailable}
          onClick=${() => this.toggleMode("actions")}>
          Events
        </button>
        <button disabled=${!sideEffectsAvailable}
          onClick=${() => this.toggleMode("side-effects")}>
          Side Effects
        </button>
      </div>
      ${state.mode == "assembly" && assemblyAvailable && m2`
        <${AssemblyDifference} rightFocus=${props.rightFocus} leftFocus=${props.leftFocus}/>`}
      ${state.mode == "registers" && registersAvailable && m2`
        <${RegisterDifference} rightFocus=${props.rightFocus} leftFocus=${props.leftFocus}/>`}
      ${state.mode == "memory" && memoryAvailable && m2`
        <${MemoryDifference} rightFocus=${props.rightFocus} leftFocus=${props.leftFocus}/>`}
      ${state.mode == "concretions" && concretionAvailable && m2`
        <${Concretions} rightFocus=${props.rightFocus} leftFocus=${props.leftFocus}/>`}
      ${state.mode == "actions" && actionsAvailable && m2`
        <${ActionDifference} rightFocus=${props.rightFocus} leftFocus=${props.leftFocus}/>`}
      ${state.mode == "side-effects" && sideEffectsAvailable && m2`
        <${SideEffectDifference} rightFocus=${props.rightFocus} leftFocus=${props.leftFocus}/>`}
      </div>`;
    }
  };

  // data/cozy-data.js
  var Status = Object.freeze({
    unloaded: Symbol("unloaded"),
    idle: Symbol("idle"),
    rendering: Symbol("rendering")
  });
  var Tidiness = Object.freeze({
    untidy: Symbol("untidy"),
    tidy: Symbol("tidy"),
    veryTidy: Symbol("very-tidy")
  });
  var View = Object.freeze({
    plain: Symbol("plain"),
    cfg: Symbol("cfg")
  });

  // data/colors.js
  var Colors = {
    defaultNode: "#ccc",
    focusedNode: "#666",
    defaultBorder: "#aaa",
    defaultEdge: "#aaa",
    focusedEdge: "#666",
    syscallNode: "#add8e6",
    focusedSyscallNode: "#00ade6",
    simprocNode: "#ade6b6",
    focusedSimprocNode: "#4eb302",
    errorNode: "#facdcd",
    focusedErrorNode: "#d00",
    assertNode: "#edcdfa",
    focusedAssertNode: "#a600de",
    postconditionNode: "#f7be6d",
    focusedPostconditionNode: "#f79000"
  };
  var colors_default = Colors;

  // components/report.js
  var NodeBadge = class extends k {
    badgeStyle(color) {
      return {
        background: color,
        color: "white",
        fontWeight: "bold",
        padding: "5px 10px 3px 10px",
        //less padding at the bottom because there's already naturally some space there for descenders.
        borderRadius: "25px",
        printColorAdjust: "exact"
      };
    }
    render(props) {
      const node = props.node;
      if (node.data("error")) {
        return m2`<span style=${this.badgeStyle(colors_default.focusedErrorNode)}>Error:</span>`;
      } else if (node.data("assertion_info")) {
        return m2`<span style=${this.badgeStyle(colors_default.focusedAssertNode)}>Assertion:</span>`;
      } else if (node.data("postcondition_info")) {
        return m2`<span style=${this.badgeStyle(colors_default.focusedPostconditionNode)}>Postcondition:</span>`;
      } else if (node.data("spinning")) {
        return m2`<span style=${this.badgeStyle(colors_default.focusedErrorNode)}>Error:</span>`;
      }
    }
  };
  var BranchData = class extends k {
    getData() {
      return this.props.node.data("error") || this.props.node.data("assertion_info") || this.props.node.data("postcondition_info") || this.props.node.data("spinning") && "Loop bounds exceeded" || null;
    }
    render(props) {
      const data = this.getData();
      if (!data)
        return;
      return m2`<div class="branch-data">
      <${NodeBadge} node=${props.node}/> ${data}
      </div>`;
    }
  };
  var ReportField = class extends k {
    onMouseEnter() {
      this.props.panel.cy.dim();
      this.props.panel.cy.highlight(this.props.leaf);
    }
    onMouseLeave() {
      this.props.panel.cy.dim();
    }
    onCheck(e22) {
      const cy = this.props.panel.cy;
      if (e22.target.checked) {
        this.props.setStatus("complete");
        cy.addCheckMark(this.props.leaf.id());
      } else {
        this.props.setStatus(void 0);
        cy.removeCheckMark(this.props.leaf.id());
      }
      this.props.refreshPrune();
    }
    onClick() {
      this.props.focus();
    }
    render(props) {
      const num = props.index + 1;
      return m2`<div class="report-field">
      <h2 
        onMouseEnter=${() => this.onMouseEnter()}
        onMouseLeave=${() => this.onMouseLeave()}
        onClick=${() => this.onClick()}
      >
        Path ${num}
      </h2>
      <${BranchData} node=${props.leaf}/>
      <form>
        <div>
        <textarea></textarea>
        </div>
        <div>
        <label for="reviewed-check">Review Complete</label>
        <input type="checkbox" onchange=${(e22) => this.onCheck(e22)} name="reviewed-check"></input>
        </div>
      </form>
    </div>`;
    }
  };
  var ReportStatus = class extends k {
    render(props) {
      return m2`<div id="report-status">
        <h3>Review Coverage: ${Math.floor(props.value * 100 / props.max)}%</h3>
        <progress value=${props.value} max=${props.max}></progress>
      </div>`;
    }
  };
  var ReportContents = class extends k {
    differenceBullets() {
      const bullets = [];
      const pruningStatus = this.props.pruningStatus;
      if (pruningStatus.pruningMemory) {
        bullets.push(m2`<li> differ with respect to final memory contents </li>`);
      }
      if (pruningStatus.pruningStdout) {
        bullets.push(m2`<li> differ with respect to stdout behavior </li>`);
      }
      if (pruningStatus.pruningRegisters) {
        bullets.push(m2`<li> differ with respect to final register contents</li>`);
      }
      if (pruningStatus.pruningEquivConstraints) {
        bullets.push(m2`<li> differ with respect to final constraints</li>`);
      }
      if (pruningStatus.pruningCorrect) {
        bullets.push(m2`<li> have an error, or correspond to an erroring branch </li>`);
      }
      if (pruningStatus.pruningDoRegex) {
        bullets.push(m2`<li> don't match the regex <code>${pruningStatus.pruningRegex}</code>, 
        or correspond to a branch that doesn't match this regex </li>`);
      }
      return bullets;
    }
    render(props) {
      const bullets = this.differenceBullets();
      return m2`
      <h3>Summary:</h3>
      <p>Comparing 
        <code> ${props.prelabel} </code>
        and
        <code> ${props.postlabel}</code>.
      </p>
      ${bullets.length > 0 && m2`<p> Limiting attention to branches that: <ul>${bullets}</ul></p>`}`;
    }
  };
  var Report = class extends k {
    constructor(props) {
      super();
      this.state = {
        branchStatuses: {}
      };
      const panel = props.data.leftPanelRef;
      this.leaves = [...panel.cy.nodes().leaves()];
    }
    componentDidMount() {
      const reportStyle = this.props.window.document.createElement("link");
      reportStyle.setAttribute("rel", "stylesheet");
      const loc = window.location;
      reportStyle.setAttribute("href", `${loc.origin}${loc.pathname}/report.css`);
      this.props.window.document.head.appendChild(reportStyle);
    }
    getReportFields() {
      const panel = this.props.data.leftPanelRef;
      return this.leaves.map((leaf, idx) => {
        return m2`<${ReportField}
        setStatus=${(status) => this.setBranchStatus(idx, status)}
        leaf=${leaf}
        focus=${() => this.props.data.focusLeafById(leaf.id())}
        panel=${panel}
        refreshPrune=${this.props.data.refreshPrune}
        index=${idx}/>`;
      });
    }
    setBranchStatus(idx, status) {
      this.setState((oldState) => ({ branchStatuses: { ...oldState.branchStatuses, [idx]: status } }));
    }
    getProgress() {
      return Object.values(this.state.branchStatuses).filter((status) => status == "complete").length;
    }
    render(props) {
      const fields = this.getReportFields();
      const progress = this.getProgress();
      return m2`<main>
        <article>
          <h1 title="report-title">Cozy Report</h1>
          <div id="summary">
            <${ReportContents}
              prelabel=${props.data.prelabel}
              postlabel=${props.data.postlabel} 
              pruningStatus=${props.data.pruningStatus}
            />
            <${ReportStatus} value=${progress} max=${fields.length} />
          </div>
          ${fields}
        </article>
      </main>`;
    }
  };

  // components/menu.js
  var Menu = class extends k {
    constructor() {
      super();
      this.button = m();
      this.options = m();
    }
    static Option = class extends k {
      render(props) {
        return m2`<div class="option"
        data-selected=${props.selected} 
        data-disabled=${props.disabled}
        onClick=${props.disabled ? null : props.onClick}>
            ${props.children}
      </div>`;
      }
    };
    componentDidUpdate() {
      if (this.props.open == this.props.title) {
        V7(this.button.current, this.options.current, {
          placement: "bottom-start"
        }).then(({ x: x11, y: y10 }) => {
          this.options.current.style.left = `${x11}px`;
          this.options.current.style.top = `${y10}px`;
        });
      }
    }
    toggleOpen() {
      if (!this.props.enabled)
        return;
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
        color: props.enabled ? "black" : "#ccc",
        backgroundColor: props.open === props.title ? "#e1e1e1" : "white"
      };
      return m2`
      <button 
        style=${menuStyle} 
        ref=${this.button} 
        onClick=${() => this.toggleOpen()}
        onMouseEnter=${() => props.open && this.props.enabled && props.setOpen(props.title)}>
        ${props.title}
      </button>
      ${props.open == props.title && m2`
        <div style=${optionStyle} ref=${this.options} class="options-wrapper">
          ${props.children}
        </div>`}`;
    }
  };

  // components/searchMenu.js
  var SearchMenu = class extends k {
    constructor() {
      super();
      this.state = {
        searchStdoutRegex: ""
      };
    }
    updateSearch(e22) {
      if (e22.target.value == "")
        this.clearSearch();
      else {
        this.setState({ searchStdoutRegex: e22.target.value }, () => {
          const cyLeft = this.props.cyLeft.cy;
          const cyRight = this.props.cyRight.cy;
          cyLeft.dim();
          cyRight.dim();
          let regex;
          try {
            regex = new RegExp(this.state.searchStdoutRegex);
          } catch (e23) {
            return;
          }
          const ltargets = cyLeft.nodes().filter((node) => node.data().stdout.match(regex));
          const rtargets = cyRight.nodes().filter((node) => node.data().stdout.match(regex));
          cyLeft.highlight(ltargets);
          cyRight.highlight(rtargets);
        });
      }
    }
    clearSearch() {
      this.setState({ searchStdoutRegex: "" }, () => {
        const cyLeft = this.props.cyLeft.cy;
        const cyRight = this.props.cyRight.cy;
        cyLeft.dim();
        cyRight.dim();
      });
      this.props.setOpen(null);
    }
    render(props, state) {
      return m2`<${Menu} 
        enabled=${props.enabled}
        open=${props.open}
        title="Search"
        setOpen=${(o13) => props.setOpen(o13)}>
        <${Menu.Option} onClick=${() => props.setOpen(null)}>
          Stdout <input 
            placeholder=".*"
            onClick=${(e22) => e22.stopPropagation()}
            onInput=${(e22) => this.updateSearch(e22)} 
            value=${state.searchStdoutRegex}/>
        <//>
        <${Menu.Option} onClick=${() => this.clearSearch(null)}>
          Clear Search 
        <//>
      <//>`;
    }
  };

  // util/constraints.js
  function constraintsEq(c1, c22) {
    if (c1.length != c22.length)
      return false;
    for (let i11 = 0; i11 < c1.length; i11++) {
      if (c1[i11] != c22[i11])
        return false;
    }
    return true;
  }

  // util/graph-tidy.js
  function removeBranch(node) {
    let target;
    while (node.outgoers("node").length == 0 && node.incomers("node").length > 0) {
      target = node;
      node = node.incomers("node")[0];
      target.remove();
    }
    if (target && node.outgoers("node").length == 0 && node.incomers("node").length == 0) {
      node.remove();
    }
  }
  var tidyMixin = {
    // array of graph elements merged out of existence
    mergedNodes: [],
    mergedEdges: [],
    // We try to tidy up a given graph by merging non-branching series of nodes
    // into single nodes
    tidy(opts) {
      const root = this.nodes().roots();
      this.tidyChildren(root, opts);
    },
    tidyChildren(node, { mergeConstraints }) {
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
            if (candidate.data("has_syscall")) {
              out[0].data().has_syscall |= candidate.data().has_syscall;
            }
            if (candidate.data("simprocs")) {
              out[0].data().simprocs.unshift(...candidate.data().simprocs);
            }
            if (candidate.data("actions")) {
              if (out[0].outgoers("edge").length)
                for (const edge of out[0].outgoers("edge")) {
                  edge.data("actions", candidate.outgoers("edge")[0].data("actions").concat(edge.data("actions")));
                }
              else {
                out[0].data("actions", candidate.outgoers("edge")[0].data("actions"));
              }
            }
            for (const parent of candidate.incomers("node")) {
              const edgeData = {
                id: `${parent.id()}-${out[0].id()}`,
                source: parent.id(),
                target: out[0].id(),
                // we copy the relevant actions (those associated with the grandparent) into the new edge
                actions: candidate.incomers("edge").data("actions")
              };
              node.cy().add({ group: "edges", data: edgeData });
            }
            if (this.root?.id() == candidate.id()) {
              this.root = out[0];
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
    },
    //merge blocks that share contents
    mergeByContents() {
      const constructed = {};
      this.mergedNodes = [];
      this.mergedEdges = [];
      for (const node of this.nodes()) {
        this.tidyStdOut(node);
      }
      for (const node of this.nodes()) {
        const addr = node.data().contents;
        console.log(addr.toString(16));
        if (addr in constructed) {
          this.mergedNodes.push(node);
          const priorStdout = constructed[addr].data("newStdout");
          if (priorStdout.length > 0) {
            constructed[addr].data("stdout", priorStdout + "\n--\n" + node.data("newStdout"));
          }
          constructed[addr].data("mergedIds", `${constructed[addr].data("mergedIds")}${node.id()}#`);
        } else {
          this.removePlainData(node);
          node.data("stdout", node.data("newStdout"));
          node.data("mergedIds", `#${node.id()}#`);
          constructed[addr] = node;
        }
        if (node.hasClass("pathHighlight"))
          constructed[addr].data("traversed", true);
        if (node.incomers().length == 0)
          constructed[addr].data("initial", true);
        if (node.outgoers().length == 0)
          constructed[addr].data("terminal", true);
      }
      const startingEdges = [...this.edges()];
      for (const edge of startingEdges) {
        const sourceRepr = constructed[edge.source().data("contents")];
        const targetRepr = constructed[edge.target().data("contents")];
        if (edge.source() == sourceRepr && edge.target() == targetRepr) {
          if (edge.hasClass("pathHighlight")) {
            edge.data("traversals", (edge.data("traversals") || 0) + 1);
          }
          edge.data("mergedIds", `#${edge.id()}#`);
        } else {
          if (sourceRepr.edgesTo(targetRepr).length > 0) {
            if (edge.hasClass("pathHighlight")) {
              const traversals = sourceRepr.edgesTo(targetRepr)[0].data("traversals");
              sourceRepr.edgesTo(targetRepr)[0].data("traversals", (traversals || 0) + 1).data("mergedIds", `${sourceRepr.edgesTo(targetRepr)[0].data("mergedIds")}${edge.id()}#`);
            }
          } else {
            this.add({
              group: "edges",
              data: {
                source: sourceRepr.id(),
                target: targetRepr.id(),
                mergedIds: `#${edge.id()}#`,
                traversals: edge.hasClass("pathHighlight") ? 1 : 0
              }
            });
          }
          this.mergedEdges.push(edge);
        }
      }
      for (const element of [...this.mergedNodes, ...this.mergedEdges]) {
        element.remove();
      }
      this.style().update();
    },
    // remove data that doesn't make sense in the CFG context
    removePlainData(node) {
      node.removeData("constraints");
      node.removeData("stdout");
      node.removeData("stderr");
    },
    // take a node from a tree, and derive what is *new* at that node
    tidyStdOut(node) {
      if (node.incomers("node").length == 1) {
        const incomerStdout = node.incomers("node")[0].data("stdout");
        node.data("newStdout", node.data("stdout").slice(incomerStdout.length, Infinity));
      } else {
        node.data("newStdout", node.data("stdout"));
      }
    },
    // tidy extraneous data added to existing elements by merging. Constructed
    // nodes are removed automatically.
    removeCFGData() {
      let element;
      while (element = this.mergedNodes.pop()) {
        element.restore();
      }
      while (element = this.mergedEdges.pop()) {
        element.restore();
      }
      for (const node of this.nodes()) {
        node.removeData("traversed");
        node.removeData("initial");
        node.removeData("terminal");
        node.removeData("mergedIds");
      }
      for (const edge of this.edges()) {
        edge.removeData("traversals");
        edge.removeData("mergedIds");
      }
    }
  };

  // components/pruneMenu.js
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
  function reviewed(leaf, other) {
    if (!leaf.data("checked") && !other.data("checked"))
      return false;
    else
      return true;
  }
  function equivConstraints(leaf, other) {
    const leftOnlyConcretions = Object.entries(leaf.data().compatibilities).flatMap(
      ([key, compat]) => key == leaf.id() ? [] : compat.conc_args
    );
    const rightOnlyConcretions = Object.entries(other.data().compatibilities).flatMap(
      ([key, compat]) => key == other.id() ? [] : compat.conc_args
    );
    return rightOnlyConcretions.length + leftOnlyConcretions.length == 0;
  }
  var matchRegex = (regexStrs) => (leaf, other) => {
    const regexes = [];
    try {
      for (const regexStr of regexStrs.split("||")) {
        regexes.push(new RegExp(regexStr));
      }
    } catch (e22) {
      if (matchRegex.debounce)
        return;
      matchRegex.debounce = true;
      alert("Unreadable Regular Expression");
      setTimeout(() => matchRegex.debounce = false, 500);
    }
    for (const regex of regexes) {
      if (leaf.data().stdout.match(regex) && other.data().stdout.match(regex)) {
        return noErrors(leaf, other);
      }
    }
    return false;
  };
  var PruneMenu = class extends k {
    constructor() {
      super();
      this.state = {
        pruningMemory: false,
        pruningStdout: false,
        pruningRegisters: false,
        pruningCorrect: false,
        pruningDoRegex: false,
        pruningChecked: false,
        pruningEquivConstraints: false,
        pruningRegex: ".*",
        awaitingPrune: null
      };
      this.prune.bind(this);
    }
    // prune all branches whose compatibilities all fail some test (e.g. all have
    // the same memory contents as the given branch)
    prune(test) {
      const leaves1 = this.props.cyLeft.cy.nodes().leaves();
      const leaves2 = this.props.cyRight.cy.nodes().leaves();
      for (const leaf of [...leaves1, ...leaves2]) {
        let flag = true;
        let other = leaf.cy() == this.props.cyLeft.cy ? this.props.cyRight.cy : this.props.cyLeft.cy;
        for (const key in leaf.data().compatibilities) {
          const otherleaf = other.nodes(`#${key}`);
          if (otherleaf.length == 0)
            continue;
          flag &&= test(leaf, otherleaf);
        }
        if (flag)
          removeBranch(leaf);
      }
      this.props.cyLeft.cy.refocus();
      this.props.cyRight.cy.refocus();
    }
    setPrune(update) {
      this.setState(update, () => {
        this.props.viewMenu.current.retidy();
        this.props.refreshLayout();
        this.doPrune();
      });
    }
    doPrune() {
      let test = () => false;
      const extendTest = (f11, g9) => (l11, r10) => f11(l11, r10) || g9(l11, r10);
      if (this.state.pruningMemory)
        test = extendTest(noMemoryDiffs, test);
      if (this.state.pruningStdout)
        test = extendTest(noStdDiffs, test);
      if (this.state.pruningEquivConstraints)
        test = extendTest(equivConstraints, test);
      if (this.state.pruningRegisters)
        test = extendTest(noRegisterDiffs, test);
      if (this.state.pruningCorrect)
        test = extendTest(noErrors, test);
      if (this.state.pruningChecked)
        test = extendTest(reviewed, test);
      if (this.state.pruningDoRegex)
        test = extendTest(matchRegex(this.state.pruningRegex), test);
      this.prune(test);
    }
    debounceRegex(e22) {
      this.setState({ pruningRegex: e22.target.value });
      if (this.state.pruningDoRegex) {
        this.setState({ awaitingPrune: true });
        clearTimeout(this.regexDebounceTimeout);
        this.regexDebounceTimeout = setTimeout(() => this.setPrune({ awaitingPrune: null }), 500);
      }
    }
    render(props, state) {
      return m2`<${Menu} 
        enabled=${props.enabled}
        open=${props.open}
        title="Prune"
        setOpen=${(o13) => props.setOpen(o13)}>
        <${Menu.Option} onClick=${() => this.setPrune({ pruningMemory: !state.pruningMemory })}>
          <input type="checkbox" checked=${state.pruningMemory}/> Identical Memory
        <//>
        <${Menu.Option} onClick=${() => this.setPrune({ pruningRegisters: !state.pruningRegisters })}>
          <input type="checkbox" checked=${state.pruningRegisters}/> Identical Register Contents 
        <//>
        <${Menu.Option} onClick=${() => this.setPrune({ pruningStdout: !state.pruningStdout })}>
          <input type="checkbox" checked=${state.pruningStdout}/> Identical Stdout/Stderr
        <//>
        <${Menu.Option} onClick=${() => this.setPrune({ pruningCorrect: !state.pruningCorrect })}>
          <input type="checkbox" checked=${state.pruningCorrect}/> Error-free
        <//>
        <${Menu.Option} onClick=${() => this.setPrune({ pruningEquivConstraints: !state.pruningEquivConstraints })}>
          <input type="checkbox" checked=${state.pruningEquivConstraints}/> Equivalent Constraints
        <//>
        <${Menu.Option} onClick=${() => this.setPrune({ pruningChecked: !state.pruningChecked })}>
          <input type="checkbox" checked=${state.pruningChecked}/> Reviewed
        <//>
        <${Menu.Option} onClick=${() => this.setPrune({ pruningDoRegex: !state.pruningDoRegex })}>
          <input type="checkbox" checked=${state.pruningDoRegex}/> Both Stdout Matching <input 
            data-awaiting=${state.awaitingPrune}
            onClick=${(e22) => e22.stopPropagation()}
            onInput=${(e22) => this.debounceRegex(e22)} 
            value=${state.pruningRegex}/>
        <//>
      <//>`;
    }
  };

  // util/graphStyle.js
  var settings = {
    showingSimprocs: true,
    showingSyscalls: true,
    showingErrors: true,
    showingAsserts: true,
    showingPostconditions: true
  };
  var style = [
    {
      selector: "node",
      style: {
        "shape": "round-rectangle",
        "background-color": colors_default.defaultNode,
        "border-color": colors_default.defaultBorder
      }
    },
    {
      selector: "[[outdegree = 0]], node[?terminal]",
      style: { "border-width": "5px" }
    },
    {
      selector: "node[?initial]",
      style: { "border-width": "5px" }
    },
    {
      selector: "edge",
      style: {
        "width": 3,
        "line-color": colors_default.defaultEdge,
        "target-arrow-color": colors_default.defaultEdge,
        "target-arrow-shape": "triangle",
        "arrow-scale": 1.5,
        "source-distance-from-node": "5px",
        "target-distance-from-node": "5px",
        "curve-style": "bezier"
      }
    },
    {
      selector: "edge.pathHighlight, edge[traversals > 0]",
      style: {
        "width": 3,
        "line-color": colors_default.focusedEdge,
        "target-arrow-color": colors_default.focusedEdge,
        "z-compound-depth": "top"
      }
    },
    {
      selector: "node.pathHighlight, node[?traversed]",
      style: {
        "background-color": colors_default.focusedNode,
        "z-compound-depth": "top"
      }
    },
    {
      selector: "node[?has_syscall]",
      style: {
        "background-color": () => settings.showingSyscalls ? colors_default.syscallNode : colors_default.defaultNode
      }
    },
    {
      selector: "node.pathHighlight[?has_syscall]",
      style: {
        "background-color": () => settings.showingSyscalls ? colors_default.syscallNode : colors_default.focusedNode
      }
    },
    {
      selector: "node[simprocs.length > 0]",
      style: {
        "background-color": () => settings.showingSimprocs ? colors_default.simprocNode : colors_default.defaultNode
      }
    },
    {
      selector: "node.pathHighlight[simprocs.length > 0]",
      style: {
        "background-color": () => settings.showingSimprocs ? colors_default.simprocNode : colors_default.focusedNode
      }
    },
    {
      selector: "node.temporaryFocus",
      style: {
        "underlay-color": "#708090",
        "underlay-opacity": 0.5
      }
    },
    {
      selector: "node[?assertion_info]",
      style: {
        "background-color": () => settings.showingAsserts ? colors_default.assertNode : colors_default.defaultNode
      }
    },
    {
      selector: "node.pathHighlight[?assertion_info]",
      style: {
        "border-width": "0px",
        "background-color": () => settings.showingAsserts ? colors_default.focusedAssertNode : colors_default.focusedNode
      }
    },
    {
      selector: "node[?postcondition_info]",
      style: {
        "background-color": () => settings.showingPostconditions ? colors_default.postconditionNode : colors_default.defaultNode
      }
    },
    {
      selector: "node.pathHighlight[?postcondition_info]",
      style: {
        "border-width": "0px",
        "background-color": () => settings.showingPostconditions ? colors_default.focusedPostconditionNode : colors_default.focusedNode
      }
    },
    {
      selector: "node[?error]",
      style: {
        "border-width": "0px",
        "background-color": () => settings.showingErrors ? colors_default.errorNode : colors_default.defaultNode
      }
    },
    {
      selector: "node[?spinning]",
      style: {
        "shape": "vee",
        "width": 50,
        "height": 50,
        "background-color": () => settings.showingErrors ? colors_default.errorNode : colors_default.defaultNode
      }
    },
    {
      selector: "node.pathHighlight[?error],node.pathHighlight[?spinning]",
      style: {
        "border-width": "0px",
        "background-color": () => settings.showingErrors ? colors_default.focusedErrorNode : colors_default.focusedNode
      }
    },
    {
      selector: "node.availablePath",
      style: {
        "border-width": "12px",
        "width": 25,
        "height": 25,
        "border-color": colors_default.focusedNode,
        "underlay-padding": "15px"
      }
    },
    {
      //we don't display checks in CFG mode, since we don't really have
      //meaningful branches there.
      selector: "node[?checked][^mergedIds]",
      style: {
        "label": "\xD7",
        "font-size": "36px",
        "text-halign": "center",
        "text-valign": "center"
      }
    },
    {
      selector: "node.pathHighlight[?checked]",
      style: {
        "color": "white"
      }
    }
  ];

  // components/viewMenu.js
  function MenuBadge(props) {
    return m2`<svg width="10" height="10">
    <rect x="1" y="1" rx="2" ry="2" width="8" height="8"
    style="fill:${props.color}" />
  </svg>`;
  }
  var ViewMenu = class extends k {
    constructor() {
      super();
      this.state = {
        showingSyscalls: true,
        // we start with syscalls visible
        showingSimprocs: true,
        // we start with SimProcedure calls visible
        showingErrors: true,
        // we start with errors visible
        showingAsserts: true,
        // we start with asserts visible
        showingPostconditions: true,
        // we start with postconditions visible
        tidiness: Tidiness.untidy
        // we're not yet tidying anything
      };
      this.toggleErrors = this.toggleErrors.bind(this);
      this.togglePostconditions = this.togglePostconditions.bind(this);
      this.toggleView = this.toggleView.bind(this);
      this.toggleSyscalls = this.toggleSyscalls.bind(this);
      this.toggleSimprocs = this.toggleSimprocs.bind(this);
      this.toggleAsserts = this.toggleAsserts.bind(this);
    }
    componentDidUpdate(_prevProps, prevState) {
      if (prevState.tidiness !== this.state.tidiness) {
        this.props.pruneMenu.current.doPrune();
        this.props.refreshLayout();
      }
    }
    retidy() {
      this.setTidiness(this.state.tidiness);
    }
    setTidiness(tidiness) {
      this.props.batch(() => {
        this.props.cyLeft.cy.json({ elements: JSON.parse(this.props.cyLeft.orig).elements });
        this.props.cyRight.cy.json({ elements: JSON.parse(this.props.cyRight.orig).elements });
        this.props.cyLeft.cy.nodes().map((node) => node.ungrabify());
        this.props.cyRight.cy.nodes().map((node) => node.ungrabify());
        this.props.cyLeft.cy.restoreCheckMarks();
        switch (tidiness) {
          case Tidiness.untidy:
            break;
          case Tidiness.tidy:
            this.tidy({});
            break;
          case Tidiness.veryTidy:
            this.tidy({ mergeConstraints: true });
            break;
        }
        this.setState({ tidiness }, this.props.regenerateFocus);
      });
    }
    tidy(opts) {
      this.props.cyLeft.cy.tidy(opts);
      this.props.cyRight.cy.tidy(opts);
      this.props.cyLeft.cy.refocus().fit();
      this.props.cyRight.cy.refocus().fit();
    }
    toggleView(type) {
      this.setState((oldState) => {
        settings[type] = !oldState[type];
        this.props.cyLeft.cy.style().update();
        this.props.cyRight.cy.style().update();
        return {
          [type]: !oldState[type]
        };
      });
    }
    toggleSyscalls() {
      this.toggleView("showingSyscalls");
    }
    toggleSimprocs() {
      this.toggleView("showingSimprocs");
    }
    toggleErrors() {
      this.toggleView("showingErrors");
    }
    toggleAsserts() {
      this.toggleView("showingAsserts");
    }
    togglePostconditions() {
      this.toggleView("showingPostconditions");
    }
    render(props, state) {
      return m2`<${Menu}
        enabled=${props.enabled}
        open=${props.open}
        title="View"
        setOpen=${(o13) => props.setOpen(o13)}>
        <${Menu.Option} 
          onClick=${() => state.tidiness !== Tidiness.untidy && this.setTidiness(Tidiness.untidy)}
          selected=${state.tidiness == Tidiness.untidy}>
            Show All Blocks
        <//>
        <${Menu.Option} 
          onClick=${() => state.tidiness !== Tidiness.tidy && this.setTidiness(Tidiness.tidy)}
          selected=${state.tidiness == Tidiness.tidy}>
            Merge Unless Constaints Change
        <//>
        <${Menu.Option} 
          onClick=${() => state.tidiness !== Tidiness.veryTidy && this.setTidiness(Tidiness.veryTidy)}
          selected=${state.tidiness == Tidiness.veryTidy}>
            Merge Unless Branching Occurs
        <//>
        <hr/>
        <${Menu.Option} 
          onClick=${this.toggleSyscalls}
          selected=${state.showingSyscalls}>
            <${MenuBadge} color=${colors_default.focusedSyscallNode}/> Show Syscalls
        <//>
        <${Menu.Option} 
          onClick=${this.toggleSimprocs}
          selected=${state.showingSimprocs}>
            <${MenuBadge} color=${colors_default.focusedSimprocNode}/> Show SimProcedure calls
        <//>
        <${Menu.Option} 
          onClick=${this.toggleErrors}
          selected=${state.showingErrors}>
            <${MenuBadge} color=${colors_default.focusedErrorNode}/> Show Errors
        <//>
        <${Menu.Option} 
          onClick=${this.toggleAsserts}
          selected=${state.showingAsserts}>
            <${MenuBadge} color=${colors_default.focusedAssertNode}/> Show Asserts
        <//>
        <${Menu.Option} 
          onClick=${this.togglePostconditions}
          selected=${state.showingPostconditions}>
            <${MenuBadge} color=${colors_default.focusedPostconditionNode}/> Show Postcondition failures
        <//>
      <//>`;
    }
  };

  // data/layouts.js
  var breadthFirst = {
    name: "breadthfirst",
    directed: true,
    spacingFactor: 2
  };
  var cola = {
    name: "cola"
  };
  var cose = {
    name: "cose",
    nodeRepulsion: function() {
      return 1e4;
    },
    idealEdgeLength: function() {
      return 64;
    },
    edgeElasticity: function() {
      return 128;
    }
  };

  // components/layoutMenu.js
  var LayoutMenu = class extends k {
    render(props) {
      return m2`
      <${Menu} 
        enabled=${props.enabled}
        open=${props.open}
        title="Layout"
        setOpen=${(o13) => props.setOpen(o13)}>
        <${Menu.Option} 
          onClick=${() => props.resetLayout(breadthFirst, View.plain)}
          selected=${props.layout.name == "breadthfirst" && props.view == View.plain}>
            Tree
        <//>
        <${Menu.Option} 
          onClick=${() => props.resetLayout(breadthFirst, View.cfg)}
          selected=${props.layout.name == "breadthfirst" && props.view == View.cfg}>
            CFG - Tree layout
        <//>
        <${Menu.Option} onClick=${() => props.resetLayout()}
          onClick=${() => props.resetLayout(cose, View.cfg)}
          selected=${props.layout.name == "cose" && props.view == View.cfg}>
            CFG - Cose layout
        <//>
        <${Menu.Option} 
          onClick=${() => props.resetLayout(cola, View.cfg)}
          selected=${props.layout.name == "cola" && props.view == View.cfg}>
            CFG - Cola layout
        <//>
        <${Menu.Option} onClick=${() => props.resetLayout()}>
            Refresh
        <//>
      <//>`;
    }
  };

  // components/menuBar.js
  var MenuBar = class extends k {
    constructor() {
      super();
      this.state = {
        open: null,
        searchStdoutRegex: ".*"
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
    setOpen(open2) {
      this.setState({ open: open2 });
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
    resetLayout(layout, view) {
      this.props.resetLayout(layout, view);
      this.setOpen(null);
    }
    saveFile(data) {
      const filename = prompt("please provide a filename");
      var blob = new Blob([data], { type: "text/json" }), a10 = document.createElement("a");
      a10.download = filename;
      a10.href = window.URL.createObjectURL(blob);
      a10.dataset.downloadurl = ["text/json", a10.download, a10.href].join(":");
      a10.dispatchEvent(new MouseEvent("click"));
    }
    openReport() {
      this.reportWindow = open();
      if (!this.reportWindow) {
        alert("couldn't open report - double check that cozy has permission to open new windows in your popup-blocker");
      }
      q(
        m2`<${Report} 
      data=${this.props.getReportInterface()} 
      window=${this.reportWindow}/>`,
        this.reportWindow.document.body
      );
    }
    render(props, state) {
      const enabled = props.status === Status.idle;
      return m2`<div id="menubar"
        onMousedown=${(ev) => this.handleLocalClick(ev)}
      >
      <${Menu} 
        enabled=${enabled}
        open=${state.open}
        title="Files"
        setOpen=${(o13) => this.setOpen(o13)}>
        <${Menu.Option} onClick=${() => this.saveFile(props.getJSON())}>
          Save Graph
        <//>
        <${Menu.Option} disabled=${props.view != View.plain} onClick=${() => this.openReport()}>
          Open New Report
        <//>
      <//>
      <${ViewMenu}
        ref=${props.viewMenu}
        enabled=${enabled && props.view == View.plain} 
        tidiness=${props.tidiness}
        pruneMenu=${props.pruneMenu}
        cyLeft=${props.cyLeft}
        cyRight=${props.cyRight}
        open=${state.open}
        regenerateFocus=${props.regenerateFocus}
        refreshLayout=${props.refreshLayout}
        batch=${props.batch}
        setOpen=${(o13) => this.setOpen(o13)}
      />
      <${PruneMenu} 
        ref=${props.pruneMenu}
        enabled=${enabled && props.view == View.plain} 
        viewMenu=${props.viewMenu}
        cyLeft=${props.cyLeft}
        cyRight=${props.cyRight}
        refreshLayout=${props.refreshLayout}
        open=${state.open}
        setOpen=${(o13) => this.setOpen(o13)}
      />
      <${LayoutMenu}
        open=${state.open}
        enabled=${enabled}
        setOpen=${(o13) => this.setOpen(o13)}
        layout=${props.layout}
        view=${props.view}
        resetLayout=${(o13, v12) => this.resetLayout(o13, v12)}
      />
      <${SearchMenu}
        enabled=${enabled}
        open=${state.open}
        setOpen=${(o13) => this.setOpen(o13)}
        cyLeft=${props.cyLeft}
        cyRight=${props.cyRight}
      />
    </div>`;
    }
  };

  // util/focusMixin.js
  var focusMixin = {
    focus(loci) {
      if (!loci)
        return;
      this.loci = loci;
      this.root = this.nodes().roots()[0];
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
    // focus a range of nodes, and set its lower tips to be the loci
    focusRange(nodes) {
      this.elements().removeClass("pathHighlight");
      this.elements().removeClass("availablePath");
      this.loci = nodes.filter(
        (ele) => ele.outgoers("node").intersection(nodes).length == 0
      );
      this.root = nodes.filter(
        (ele) => ele.incomers("node").intersection(nodes).length == 0
      );
      nodes.addClass("pathHighlight");
      if (this.loci.length > 1) {
        for (const locus of this.loci) {
          locus.removeClass("pathHighlight");
          locus.addClass("availablePath");
        }
      } else {
        this.loci.addClass("pathHighlight");
      }
    },
    refocus() {
      this.elements().removeClass("pathHighlight").removeClass("availablePath");
      if (this.root?.incomers?.().length > 0 || this.loci?.outgoers?.().length > 0) {
        this.focusRange(this.getRangeOf(this.loci));
      } else {
        this.focus(this.loci);
      }
      return this;
    },
    highlight(nodes) {
      nodes.addClass("temporaryFocus");
    },
    dim() {
      this.elements().removeClass("temporaryFocus");
    },
    blur() {
      this.loci = null;
      this.root = null;
      this.elements().removeClass("pathHighlight").removeClass("availablePath");
      this.elements().removeData("traversals");
      return this;
    }
  };

  // util/checkedMixin.js
  var checkedMixin = {
    checkedIds: /* @__PURE__ */ new Set(),
    setCheckMarks(nodes) {
      this.nodes().removeData("checked");
      this.checkedIds = /* @__PURE__ */ new Set([...nodes.map((node) => node.id())]);
      nodes.data("checked", true);
    },
    addCheckMark(id) {
      this.checkedIds.add(id);
      this.nodes(`#${id}`).data("checked", true);
    },
    removeCheckMark(id) {
      this.checkedIds.delete(id);
      this.nodes(`#${id}`).data("checked", false);
      this.nodes(`#${id}`).removeData("checked");
    },
    restoreCheckMarks() {
      this.setCheckMarks(this.filter((node) => this.checkedIds.has(node.id())));
    }
  };

  // util/segmentationMixin.js
  var segmentationMixin = {
    // XXX: It would be possible to memoize on constraints here, but that adds
    // some complexity when the granularity of the graph changes
    // 
    // The connector is an extra function that we can use to potentially link
    // segments with different constraints under some conditions
    getRangeOf(node, connector) {
      const constraints = node.data().constraints;
      let target = node;
      while (target.incomers("node").length == 1 && constraintsEq(constraints, target.incomers("node")[0].data().constraints)) {
        target = target.incomers("node")[0];
      }
      let generations = [[target]];
      while (true) {
        const lastGen = generations[generations.length - 1];
        const nextGen = lastGen.flatMap(
          (n13) => n13.outgoers("node").filter((outgoer) => {
            if (constraintsEq(outgoer.data().constraints, n13.data().constraints))
              return true;
            if (connector?.(outgoer, n13))
              return true;
          }).toArray()
        );
        if (nextGen.length > 0)
          generations.push(nextGen);
        else
          break;
      }
      generations = generations.flat();
      return this.collection(generations);
    },
    segmentToRange(segment) {
      return segment.bot.predecessors("node").intersection(segment.top.successors("node")).union(segment.top).union(segment.bot);
    },
    rangeToSegment(range) {
      return {
        bot: range.filter((ele) => ele.outgoers("node").intersection(range).length == 0)[0],
        top: range.filter((ele) => ele.incomers("node").intersection(range).length == 0)[0]
      };
    },
    // this shows a generalized segment, in which we ignore additional
    // constraints that don't narrow the pool of compatible nodes on the opposite
    // side.
    getCompatibilityRangeOf(node, cy) {
      const connector = (n13, o13) => {
        const ncompat = this.getLeavesCompatibleWith(n13, cy);
        const ocompat = this.getLeavesCompatibleWith(o13, cy);
        return ncompat.size == ocompat.size;
      };
      return this.getRangeOf(node, connector);
    },
    // gets all leaves in cy compatible with a given node
    //
    // XXX : this should probably be disabled when pruning is in progress, it
    // doesn't necessarily make sense once nodes have been removed.
    getLeavesCompatibleWith(node, cy) {
      const leaves = node.successors().add(node).leaves();
      const ids = leaves.flatMap((leaf) => Object.keys(leaf.data().compatibilities)).map((s11) => `#${s11}`);
      const compats = /* @__PURE__ */ new Set();
      for (const id of ids) {
        compats.add(cy.$(id)[0]);
      }
      return compats;
    },
    // in a preorder, find the greatest/lowest element p such that each element of leaves
    // is > p; i.e the strongest set of constraints implied by the constraints on
    // each member of leaves
    getMinimalCeiling(leaves) {
      let depth = 1;
      const [canonicalLeaf] = leaves;
      const canonicalPreds = canonicalLeaf.predecessors("node");
      if (leaves.size === 1)
        return canonicalLeaf;
      while (true) {
        for (const leaf of leaves) {
          const preds = leaf.predecessors("node");
          if (depth > preds.length || preds[preds.length - depth] !== canonicalPreds[canonicalPreds.length - depth]) {
            return canonicalPreds[canonicalPreds.length - (depth - 1)];
          }
        }
        depth += 1;
      }
    }
  };

  // components/app.js
  Pl.use(e17);
  var App = class extends k {
    constructor() {
      super();
      this.state = {
        status: Status.unloaded,
        // awaiting graph data
        layout: breadthFirst,
        // we start with the breadthfirst layout
        view: View.plain,
        //we start with all nodes visible, not a CFG
        prelabel: "prepatch",
        postlabel: "postpatch"
      };
      this.cy1 = m();
      this.cy2 = m();
      this.cy1.other = this.cy2;
      this.cy2.other = this.cy1;
      this.tooltip = m();
      this.handleDragleave = this.handleDragleave.bind(this);
      this.handleDragover = this.handleDragover.bind(this);
      this.clearTooltip = this.clearTooltip.bind(this);
      this.resetLayout = this.resetLayout.bind(this);
      this.getJSON = this.getJSON.bind(this);
      this.viewMenu = m();
      this.pruneMenu = m();
      window.app = this;
    }
    // Produces an object encapsulating data and methods needed by a cozy report
    // window.
    getReportInterface() {
      return {
        prelabel: this.state.prelabel,
        postlabel: this.state.postlabel,
        pruningStatus: this.pruneMenu.current.state,
        leftPanelRef: this.cy1,
        refreshPrune: () => {
          if (this.pruneMenu.current.state.pruningChecked) {
            this.pruneMenu.current.setPrune({});
          }
        },
        focusLeafById: (id) => {
          const leaf = this.cy1.cy.nodes(`#${id}`);
          const selfCy = this.cy1.cy;
          const otherCy = this.cy2.cy;
          const selfRoot = selfCy.nodes().roots()[0];
          const selfSegment = new Segment(selfRoot, leaf);
          const compatibilities = leaf.data().compatibilities;
          selfCy.blur().focus(leaf);
          otherCy.blur().focus(otherCy.nodes().filter((node) => +node.data().id in compatibilities));
          this.setState({ leftFocus: selfSegment, rightFocus: null });
        }
      };
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
        }).catch((e22) => console.error(e22));
      }
      if (isServedPost) {
        fetch(isServedPost).then((rslt) => rslt.json()).then((raw) => {
          const obj = JSON.parse(raw);
          if (!obj.elements)
            throw new Error("Malformed post-patch JSON");
          this.mountToCytoscape(obj, this.cy2);
        }).catch((e22) => console.error(e22));
      }
    }
    handleClick(ev) {
      if (this.state.status == Status.unloaded) {
        alert("Please load both graphs before attempting comparison.");
        return;
      }
      if (this.state.view == View.plain)
        this.handlePlainClick(ev);
      if (this.state.view == View.cfg)
        this.handleCFGClick(ev);
    }
    handleCFGClick(ev) {
      if (!ev.originalEvent.shiftKey)
        return;
      const addr = ev.target.data("address");
      this.resetLayout(breadthFirst, View.plain);
      const similar = ev.target.cy().nodes(`[address=${addr}]`);
      ev.target.cy().highlight(similar);
    }
    handlePlainClick(ev) {
      const isLeft = ev.target.cy() == this.cy1.cy;
      const self2 = ev.cy;
      const other = ev.cy.ref.other.cy;
      const segmentSelect = ev.originalEvent.shiftKey;
      const refining = self2.loci?.includes(ev.target) && self2.loci.length > 1 && segmentSelect == this.lastSegmentSelect;
      this.lastSegmentSelect = segmentSelect;
      let selfSegment;
      if (segmentSelect) {
        selfSegment = Segment.fromRange(self2.getRangeOf(ev.target));
        self2.blur().focusRange(self2.getRangeOf(ev.target));
      } else {
        if (ev.target.outgoers().length !== 0)
          return;
        const selfRoot = ev.cy.nodes().roots()[0];
        selfSegment = new Segment(selfRoot, ev.target);
        self2.blur().focus(ev.target);
      }
      if (isLeft)
        this.setState({ leftFocus: selfSegment });
      else
        this.setState({ rightFocus: selfSegment });
      if (!refining) {
        let otherSegment;
        if (segmentSelect) {
          const compats = self2.getLeavesCompatibleWith(ev.target, other);
          const otherRange = other.getCompatibilityRangeOf(self2.getMinimalCeiling(compats), self2);
          other.blur().focusRange(otherRange);
          if (other.loci.length == 1) {
            otherSegment = Segment.fromRange(otherRange);
          }
        } else {
          const compatibilities = ev.target.data().compatibilities;
          other.blur().focus(other.nodes().filter((node) => +node.data().id in compatibilities));
          if (other.loci.length == 1) {
            const otherRoot = other.nodes().roots()[0];
            otherSegment = new Segment(otherRoot, other.loci);
          }
        }
        if (otherSegment) {
          if (isLeft)
            this.setState({ rightFocus: otherSegment });
          else
            this.setState({ leftFocus: otherSegment });
        } else {
          if (isLeft)
            this.setState({ rightFocus: null, leftFocus: selfSegment });
          else
            this.setState({ leftFocus: null, rightFocus: selfSegment });
        }
      }
    }
    getJSON() {
      return JSON.stringify({
        pre: {
          data: JSON.parse(this.cy1.orig),
          name: this.state.prelabel
        },
        post: {
          data: JSON.parse(this.cy2.orig),
          name: this.state.postlabel
        }
      });
    }
    setStatus(status) {
      this.setState({ status });
    }
    regenerateFocus() {
      const connectedLeft = this.cy1.cy.loci?.filter((node) => node.inside());
      const connectedRight = this.cy2.cy.loci?.filter((node) => node.inside());
      if (connectedLeft?.length == 0 || connectedRight?.length == 0) {
        this.cy1.cy.blur();
        this.cy2.cy.blur();
        this.setState({ leftFocus: null, rightFocus: null });
      } else {
        this.setState({
          leftFocus: this.state.leftFocus ? new Segment(this.cy1.cy.root, this.cy1.cy.loci) : null,
          rightFocus: this.state.rightFocus ? new Segment(this.cy2.cy.root, this.cy2.cy.loci) : null
        });
      }
    }
    async handleDrop(ev) {
      ev.stopPropagation();
      ev.preventDefault();
      ev.currentTarget.classList.remove("dragHover");
      const file = ev.dataTransfer.files[0];
      const raw = await file.text().then(JSON.parse);
      this.setState({
        prelabel: raw.pre.name,
        postlabel: raw.post.name
      });
      this.mountToCytoscape(raw.pre.data, this.cy1);
      this.mountToCytoscape(raw.post.data, this.cy2);
    }
    handleDragover(ev) {
      ev.stopPropagation();
      ev.preventDefault();
      ev.currentTarget.classList.add("dragHover");
    }
    handleDragleave(ev) {
      ev.stopPropagation();
      ev.preventDefault();
      ev.currentTarget.classList.remove("dragHover");
    }
    mountToCytoscape(raw, ref) {
      if (ref.cy)
        ref.cy.destroy();
      const cy = Pl({
        style,
        elements: raw.elements
      });
      cy.mount(ref.current);
      Object.assign(cy, focusMixin);
      Object.assign(cy, tidyMixin);
      Object.assign(cy, segmentationMixin);
      Object.assign(cy, checkedMixin);
      cy.debugData = cy.nodes().roots()[0].data("debug");
      ref.currentLayout = cy.layout(this.state.layout).run();
      cy.on("add", (ev) => {
        if (ev.target.group() === "nodes") {
          this.initializeNode(ev.target);
        }
      });
      cy.on("click", (ev) => {
        if (this.state.view == View.cfg)
          return;
        if (!ev.target.group) {
          this.batch(() => {
            this.cy1.cy?.blur();
            this.cy2.cy?.blur();
            this.setState({ leftFocus: null, rightFocus: null });
            this.tooltip.current.clearTooltip();
          });
        }
      });
      cy.on("zoom pan", () => {
        this.tooltip.current.clearTooltip();
      });
      ref.cy = cy;
      ref.orig = JSON.stringify(cy.json());
      cy.ref = ref;
      cy.nodes().map((node) => this.initializeNode(node));
      this.setState({
        status: !this.cy1.cy || !this.cy2.cy ? Status.unloaded : Status.idle
      });
    }
    initializeNode(node) {
      node.ungrabify();
      node.on("mouseout", (ev) => {
        ev.cy.container().style.cursor = "default";
      });
      node.on("mouseover", (ev) => {
        if (ev.target.outgoers().length == 0) {
          ev.cy.container().style.cursor = "pointer";
        }
        this.tooltip.current.attachTo(ev.target);
      });
      node.on("click", (ev) => this.handleClick(ev));
    }
    startRender(method) {
      this.setState({ status: Status.rendering }, method);
    }
    batch(cb) {
      this.cy1.cy?.startBatch();
      this.cy2.cy?.startBatch();
      cb();
      this.cy1.cy?.endBatch();
      this.cy2.cy?.endBatch();
    }
    resetLayout(layout, view) {
      this.setState((oldState) => {
        this.cy1.currentLayout.stop();
        this.cy2.currentLayout.stop();
        layout = layout ?? oldState.layout;
        if (view != oldState.view) {
          if (view == View.cfg) {
            this.cy1.cy.mergeByContents();
            this.cy2.cy.mergeByContents();
          } else if (view == View.plain) {
            this.cy1.cy.removeCFGData();
            this.cy2.cy.removeCFGData();
            this.viewMenu.current.retidy();
            this.pruneMenu.current.doPrune();
          } else {
            view = oldState.view;
          }
        }
        this.cy1.currentLayout = this.cy1.cy.layout(layout).run();
        this.cy2.currentLayout = this.cy2.cy.layout(layout).run();
        return { view, layout };
      });
    }
    refreshLayout() {
      this.cy1.currentLayout = this.cy1.cy.layout(this.state.layout).run();
      this.cy2.currentLayout = this.cy2.cy.layout(this.state.layout).run();
    }
    clearTooltip() {
      this.tooltip.current.clearTooltip();
    }
    render(_props, state) {
      return m2`
      <${Tooltip} ref=${this.tooltip}/>
      <${MenuBar} 
        cyLeft=${this.cy1}
        cyRight=${this.cy2}
        view=${state.view}
        layout=${state.layout}
        getReportInterface=${() => this.getReportInterface()}
        regenerateFocus=${() => this.regenerateFocus()}
        resetLayout=${this.resetLayout}
        refreshLayout=${() => this.refreshLayout()}
        tidiness=${state.tidiness}
        status=${state.status}
        batch=${(cb) => this.batch(cb)}
        viewMenu=${this.viewMenu}
        pruneMenu=${this.pruneMenu}
        getJSON=${this.getJSON}
      />
      <div id="main-view"
        onDragover=${this.handleDragover}
        onDragleave=${this.handleDragleave}
        onDrop=${(ev) => this.startRender(() => this.handleDrop(ev))} 
      >
        <span id="labelLeft">${state.prelabel}</span>
        <span id="labelRight">${state.postlabel}</span>
        <div 
          onMouseEnter=${this.clearTooltip} 
          ref=${this.cy1}
           id="cy1">
        </div>
        <div 
          onMouseEnter=${this.clearTooltip} 
          ref=${this.cy2} id="cy2">
        </div>
      </div>
      <${DiffPanel} 
        rightFocus=${state.rightFocus}
        leftFocus=${state.leftFocus}
        onMouseEnter=${() => this.tooltip.current.clearTooltip()} 
      />
      ${state.status == Status.rendering && m2`<span id="status-indicator">rendering...</span>`}
    `;
    }
  };

  // cozy-viz.js
  q(m2`<${App}/>`, document.body);
})();
/*!
Embeddable Minimum Strictly-Compliant Promises/A+ 1.1.1 Thenable
Copyright (c) 2013-2014 Ralf S. Engelschall (http://engelschall.com)
Licensed under The MIT License (http://opensource.org/licenses/MIT)
*/
/*! Bezier curve function generator. Copyright Gaetan Renaudeau. MIT License: http://en.wikipedia.org/wiki/MIT_License */
/*! Runge-Kutta spring physics function generator. Adapted from Framer.js, copyright Koen Bok. MIT License: http://en.wikipedia.org/wiki/MIT_License */
