"""Build and validate a desk lamp in the isolated Blender Box session."""
import json
import math

import bpy
from mathutils import Vector

# This scene belongs to the fresh session created for this Run.
bpy.ops.object.select_all(action="SELECT")
bpy.ops.object.delete(use_global=False)


def material(name, color, metallic=0.0):
    mat = bpy.data.materials.new(name)
    mat.diffuse_color = (*color, 1)
    mat.use_nodes = True
    shader = mat.node_tree.nodes.get("Principled BSDF")
    shader.inputs["Base Color"].default_value = (*color, 1)
    shader.inputs["Metallic"].default_value = metallic
    shader.inputs["Roughness"].default_value = 0.28
    return mat


orange = material("Burnt orange enamel", (0.85, 0.19, 0.045), 0.25)
brass = material("Brushed brass", (0.58, 0.36, 0.12), 0.8)
cream = material("Warm ivory", (0.92, 0.82, 0.60))
charcoal = material("Deep teal", (0.045, 0.105, 0.115), 0.15)


def finish(obj, name, mat, bevel=0.0):
    obj.name = name
    obj.data.materials.append(mat)
    for face in obj.data.polygons:
        face.use_smooth = True
    if bevel:
        mod = obj.modifiers.new("Soft edges", "BEVEL")
        mod.width = bevel
        mod.segments = 4
        obj.modifiers.new("Weighted normals", "WEIGHTED_NORMAL")
    return obj


def cylinder(name, radius, depth, z, mat, bevel=0.03):
    bpy.ops.mesh.primitive_cylinder_add(
        vertices=96, radius=radius, depth=depth, location=(0, 0, z)
    )
    return finish(bpy.context.object, name, mat, bevel)


plinth = cylinder("Display plinth", 1.65, 0.18, 0.09, charcoal, 0.07)
base = cylinder("Lamp base", 0.70, 0.18, 0.27, orange, 0.07)
stem = cylinder("Brass stem", 0.105, 1.34, 1.01, brass, 0.015)
for index, z in enumerate((0.39, 0.45, 0.51), start=1):
    cylinder(f"Collar {index}", 0.15, 0.035, z, brass, 0.008)

# Revolve a dome profile into a smooth, open lampshade.
segments, rings = 96, 24
vertices = []
for row in range(rings + 1):
    angle = 0.025 + (math.pi / 2 - 0.025) * row / rings
    radius = 1.12 * math.sin(angle)
    z = 1.62 + 0.80 * math.cos(angle)
    for column in range(segments):
        turn = math.tau * column / segments
        vertices.append((radius * math.cos(turn), radius * math.sin(turn), z))
faces = []
for row in range(rings):
    for column in range(segments):
        a = row * segments + column
        b = row * segments + (column + 1) % segments
        faces.append((a, a + segments, b + segments, b))
faces.append(tuple(range(segments)))
mesh = bpy.data.meshes.new("Revolved shade mesh")
mesh.from_pydata(vertices, [], faces)
mesh.update()
shade = bpy.data.objects.new("Lamp shade", mesh)
bpy.context.collection.objects.link(shade)
finish(shade, "Lamp shade", orange)
wall = shade.modifiers.new("Shade wall", "SOLIDIFY")
wall.thickness = 0.045
rim = shade.modifiers.new("Rounded rim", "BEVEL")
rim.width, rim.segments = 0.015, 3

cylinder("Ivory diffuser", 1.06, 0.025, 1.63, cream, 0.01)
bpy.ops.mesh.primitive_torus_add(
    major_segments=96, minor_segments=16,
    location=(0, 0, 1.62), major_radius=1.105, minor_radius=0.022,
)
finish(bpy.context.object, "Brass shade trim", brass)
switch = cylinder("Power switch", 0.065, 0.045, 0.385, brass, 0.01)
switch.location.y = -0.46

# Set a repeatable studio view for both requested captures.
bpy.ops.object.select_all(action="DESELECT")
bpy.context.view_layer.objects.active = shade
view_target = Vector((0, 0, 1.20))
view_rotation = (Vector((5, -8, 4.4)) - view_target).to_track_quat("Z", "Y")
for screen in bpy.data.screens:
    for area in screen.areas:
        if area.type == "VIEW_3D":
            space = area.spaces.active
            space.overlay.show_overlays = False
            space.show_gizmo = False
            space.shading.type = "SOLID"
            space.shading.light = "STUDIO"
            space.shading.color_type = "MATERIAL"
            space.shading.show_shadows = True
            space.shading.show_cavity = True
            space.shading.cavity_type = "BOTH"
            space.shading.curvature_ridge_factor = 1.3
            space.shading.curvature_valley_factor = 1.0
            space.shading.background_type = "VIEWPORT"
            space.shading.background_color = (0.035, 0.045, 0.05)
            space.region_3d.view_rotation = view_rotation
            space.region_3d.view_distance = 6.2
            space.region_3d.view_location = view_target
            space.region_3d.view_perspective = "ORTHO"
            area.tag_redraw()

# Assert scene properties that matter to this model.
parts = [obj for obj in bpy.context.scene.objects if obj.type == "MESH"]
assert len(parts) == 10, "Expected ten lamp and display parts"
assert len(shade.data.polygons) == rings * segments + 1
assert shade.data.materials[0] == orange
assert stem.data.materials[0] == brass
assert wall.thickness > 0, "The shade needs a physical wall"
assert all(value > 0 for value in base.dimensions)

print(json.dumps({
    "schema_version": 1,
    "status": "pass",
    "scene": "Studio desk lamp",
    "mesh_objects": len(parts),
    "shade_faces": len(shade.data.polygons),
    "materials": len({slot.name for obj in parts for slot in obj.data.materials}),
}))
