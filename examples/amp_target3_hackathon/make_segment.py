import argparse
import os

from ofrak_patch_maker.toolchain.llvm_12 import LLVM_12_0_1_Toolchain

import ofrak_ghidra
from ofrak import OFRAK, OFRAKContext, Resource, ResourceFilter, ResourceAttributeValueFilter
from ofrak.core import (
    Allocatable,
    CodeRegion,
    ComplexBlock,
    Instruction,
    LiefAddSegmentConfig,
    LiefAddSegmentModifier,
    ElfProgramHeader,
)
from ofrak.core.patch_maker.modifiers import (
    PatchFromSourceModifier,
    PatchFromSourceModifierConfig,
    SourceBundle,
)
from ofrak_patch_maker.toolchain.model import (
    ToolchainConfig,
    BinFileType,
    CompilerOptimizationLevel,
    Segment,
)
from ofrak_patch_maker.toolchain.utils import get_file_format
from ofrak_type import Range
from ofrak_type.memory_permissions import MemoryPermissions

PAGE_ALIGN = 0x1000
GHIDRA_PIE_OFFSET = 0x100000  # Ghidra bases PIE executables at 0x100000

async def add_and_return_segment(elf_resource: Resource, vaddr: int, size: int) -> ElfProgramHeader:
    """Add a segment to `elf_resource`, of size `size` at virtual address `vaddr`,
    returning this new segment resource after unpacking."""

    config = LiefAddSegmentConfig(vaddr, PAGE_ALIGN, [0 for _ in range(size)], "rx")
    await elf_resource.run(LiefAddSegmentModifier, config)
    await elf_resource.unpack_recursively()

    # Get our newly added segment. First get all ElfProgramHeaders, then return the one
    # with our virtual address.
    file_segments = await elf_resource.get_descendants_as_view(
        ElfProgramHeader, r_filter=ResourceFilter(tags=(ElfProgramHeader,))
    )
    segment = [seg for seg in file_segments if seg.p_vaddr == vaddr].pop()

    # Carve out a child of the new segment where we can store the code for our new function.
    code_region = CodeRegion(segment.p_vaddr + GHIDRA_PIE_OFFSET, segment.p_filesz)
    code_region.resource = await elf_resource.create_child_from_view(
        code_region, data_range=Range(segment.p_offset, segment.p_offset + segment.p_filesz)
    )
    elf_resource.add_tag(Allocatable)
    await elf_resource.save()

    return segment

async def main(ofrak_context: OFRAKContext, file_path: str, output_file_name: str):
    try:
        root_resource = await ofrak_context.create_root_resource_from_file(file_path)
    except FileNotFoundError:
        raise RuntimeError(
            f"Cannot find the file {file_path}. Did you run the Makefile to build it?"
        )

    await add_and_return_segment(root_resource, 0x15F004, 0x2000)
    await root_resource.pack()
    await root_resource.flush_data_to_disk(output_file_name)

    assert os.path.exists(output_file_name)
    assert get_file_format(output_file_name) == BinFileType.ELF

    print(f"Done! Output file written to {output_file_name}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    ofrak = OFRAK()
    ofrak.discover(ofrak_ghidra)
    ofrak.run(main, "libroscpp_ofrak.so", "libroscpp_ofrak_modified.so")
