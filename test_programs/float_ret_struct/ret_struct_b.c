typedef struct {
    float x;
    float y;
    float z;
} Vector3;

Vector3 badCrossProduct(Vector3 a, Vector3 b) {
    Vector3 ret = {
        .x = a.y * b.z - a.z * b.y,
        .y = a.z * b.x - a.x * b.z,
        .z = a.x * b.y - a.y * b.x
    };
    ret.x = -ret.x;
    ret.y = -ret.y;
    return ret;
}